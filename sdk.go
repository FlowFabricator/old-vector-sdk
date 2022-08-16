package vsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/FlowFabricator/vector-plugins/plugins"
	"github.com/FlowFabricator/vector-plugins/states"
	"github.com/FlowFabricator/vector-sdk/sdkpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"sync"
	"time"
)

type authenticator struct {
	apiToken string
}

func (a *authenticator) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + a.apiToken,
	}, nil
}

func (authenticator) RequireTransportSecurity() bool {
	return true
}

const (
	WorkflowComplete WorkflowState = iota
	WorkflowRunning
	WorkflowFailed
	WorkflowPending
	WorkflowTriggerFailure
)

var workflowStringMap = [...]string{
	"WorkflowComplete",
	"WorkflowRunning",
	"WorkflowFailed",
	"WorkflowPending",
	"WorkflowTriggerFailure",
}

type WorkflowState uint32

func (w WorkflowState) String() string {
	return workflowStringMap[w]
}

type WorkflowStatus struct {
	State   WorkflowState
	Details string
}

var (
	ErrConnection = errors.New("connection error")

	sdkClient sdkpb.SDKClient
	envVars   map[string]string
	waitGroup sync.WaitGroup
)

type Trigger struct {
	evalFunc func() (bool, error)
}

func Call(pluginName, action string, roles []string, args plugins.Args) (states.ActionOutput, error) {
	err := createGrpcConnection(false)
	if err != nil {
		return states.ActionOutput{}, err
	}

	argsAsJson, err := json.Marshal(args)
	if err != nil {
		return states.ActionOutput{}, err
	}

	resp, err := sdkClient.Call(context.Background(), &sdkpb.CallRequest{
		RunRequest: &sdkpb.RunRequest{
			Plugin:        pluginName,
			PluginVersion: "v0.1.0",
			Action:        action,
			ArgsMapAsJson: argsAsJson,
		},
		Roles:       roles,
		StateName:   envVars["STATE_NAME"],
		ExecutionId: envVars["EXEC_ID"],
	})

	if err != nil {
		return states.ActionOutput{}, err
	}
	return states.ActionOutput{
		ExitCode: states.ActionExitCode(resp.ExitCode),
		Details:  resp.Details,
		Data:     resp.Data,
	}, nil
}

func Return(output states.StateOutput) {
	err := createGrpcConnection(false)
	if err != nil {
		panic(err)
	}

	_, err = sdkClient.Return(context.Background(), &sdkpb.ReturnInfo{
		Output: &sdkpb.StateOutput{
			ExitCode:  uint32(output.ExitCode),
			ValueType: uint32(output.DataType),
			Data:      output.Data,
		},
		StateName:   envVars["STATE_NAME"],
		ExecutionId: envVars["EXEC_ID"],
	})
	if err != nil {
		panic(err)
	}
}

func setWorkflowStatus(status WorkflowStatus) {
	err := createGrpcConnection(true)
	if err != nil {
		panic(err)
	}

	_, err = sdkClient.SetWorkflowStatus(context.Background(), &sdkpb.WorkflowStatus{
		WorkflowState: uint32(status.State),
		Details:       status.Details,
	})
	if err != nil {
		panic(err)
	}
}

func CreateTrigger(evalFunc func() (bool, error)) Trigger {
	return Trigger{
		evalFunc: evalFunc,
	}
}

func CreateWorkflow(trigger Trigger, workflow func() WorkflowStatus) {
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			triggered, err := trigger.evalFunc()
			if err != nil {
				setWorkflowStatus(WorkflowStatus{
					State:   WorkflowTriggerFailure,
					Details: err.Error(),
				})
				return
			}

			if triggered {
				status := workflow()
				setWorkflowStatus(status)
			}
		}
	}()
}

func GetData(sensor, method string, args plugins.Args) ([]byte, error) {
	err := createGrpcConnection(true)
	if err != nil {
		return nil, err
	}

	argsAsJson, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}

	resp, err := sdkClient.GetSensorData(context.Background(), &sdkpb.SensorDataRequest{
		SensorName:       sensor,
		SensorVersion:    "v0.1.0",
		SensorMethod:     method,
		SensorArgsAsJson: argsAsJson,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func ExecuteState(state string) (states.StateOutput, error) {
	err := createGrpcConnection(true)
	if err != nil {
		return states.StateOutput{}, err
	}

	out, err := sdkClient.ExecuteState(context.Background(), &sdkpb.StateDescription{
		Name: state,
	})
	if err != nil {
		return states.StateOutput{}, err
	}

	return states.StateOutput{
		ExitCode: states.StateExitCode(out.ExitCode),
		DataType: states.ValueType(out.ValueType),
		Data:     out.Data,
	}, nil
}

func WaitForWorkflows() {
	waitGroup.Wait()
}

func createGrpcConnection(forWorkflows bool) error {
	if envVars != nil && sdkClient != nil {
		return nil
	}

	vars, err := getEnvVars(forWorkflows)
	if err != nil {
		return err
	}
	envVars = vars

	var dialOpts []grpc.DialOption
	if envVars["API_TLS_CA"] != "" {
		tlsConf, err := decodeTLSConf(envVars["API_TLS_CA"], envVars["API_TLS_CERT"])
		if err != nil {
			return fmt.Errorf("failed to decode TLS config: %v", err)
		}

		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
			grpc.WithPerRPCCredentials(&authenticator{apiToken: envVars["API_TOKEN"]}),
			grpc.WithBlock(),
		}
	} else {
		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithPerRPCCredentials(&authenticator{apiToken: envVars["API_TOKEN"]}),
			grpc.WithBlock(),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := grpc.DialContext(ctx, envVars["API_SERVER_URL"], dialOpts...)
	cancel()
	if err != nil {
		return fmt.Errorf("%w: failed to dial grpc: %v", ErrConnection, err)
	}
	sdkClient = sdkpb.NewSDKClient(conn)
	return nil
}

func getEnvVars(forWorkflows bool) (map[string]string, error) {
	var nameVar string
	if forWorkflows {
		nameVar = "WORKFLOW_NAME"
	} else {
		nameVar = "STATE_NAME"
	}
	varNames := []string{nameVar, "EXEC_ID", "API_SERVER_URL", "API_TOKEN", "API_TLS_CA", "API_TLS_CERT"}
	vars := make(map[string]string)
	for _, varName := range varNames {
		value, found := os.LookupEnv(varName)
		if !found {
			if varName != "API_TLS_CA" && varName != "API_TLS_CERT" {
				return nil, fmt.Errorf("%s environment variable not set", varName)
			}
			continue
		}
		data, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 environment variable '%s': %v", varName, err)
		}
		vars[varName] = string(data)
	}
	return vars, nil
}

func decodeTLSConf(encodedCa, encodedClientCert string) (*tls.Config, error) {
	gob.Register(ed25519.PublicKey{})
	gob.Register(ed25519.PrivateKey{})

	rootCa := &x509.Certificate{}
	dec := gob.NewDecoder(bytes.NewReader([]byte(encodedCa)))
	if err := dec.Decode(rootCa); err != nil {
		return nil, err
	}

	clientCert := tls.Certificate{}
	dec = gob.NewDecoder(bytes.NewReader([]byte(encodedClientCert)))
	if err := dec.Decode(&clientCert); err != nil {
		return nil, err
	}

	rootCAPool := x509.NewCertPool()
	rootCAPool.AddCert(rootCa)
	return &tls.Config{
		RootCAs: rootCAPool,
		Certificates: []tls.Certificate{
			clientCert,
		},
	}, nil
}

func IsConnection(err error) bool {
	return errors.Is(err, ErrConnection)
}
