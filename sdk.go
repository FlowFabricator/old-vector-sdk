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
	"fmt"
	"github.com/FlowFabricator/vector-plugins/plugins"
	"github.com/FlowFabricator/vector-plugins/states"
	"github.com/FlowFabricator/vector-sdk/sdkpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"os"
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

func Call(pluginName, action string, roles []string, args plugins.Args) (states.ActionOutput, error) {
	envVars, err := getEnvVars()
	if err != nil {
		return states.ActionOutput{}, err
	}

	var dialOpts []grpc.DialOption
	if envVars["API_TLS_CA"] != "" {
		tlsConf, err := decodeTLSConf(envVars["API_TLS_CA"], envVars["API_TLS_CERT"])
		if err != nil {
			return states.ActionOutput{}, fmt.Errorf("failed to decode TLS config: %v", err)
		}

		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
			grpc.WithPerRPCCredentials(&authenticator{apiToken: envVars["API_TOKEN"]}),
			grpc.WithBlock(),
		}
	} else {
		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := grpc.DialContext(ctx, envVars["API_SERVER_URL"], dialOpts...)
	cancel()
	if err != nil {
		return states.ActionOutput{}, fmt.Errorf("failed to dial grpc: %v", err)
	}

	argsAsJson, err := json.Marshal(args)
	if err != nil {
		return states.ActionOutput{}, err
	}

	sdkClient := sdkpb.NewSDKClient(conn)
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

func getEnvVars() (map[string]string, error) {
	varNames := []string{"STATE_NAME", "EXEC_ID", "API_SERVER_URL", "API_TOKEN", "API_TLS_CA", "API_TLS_CERT"}
	envVars := make(map[string]string)
	for _, varName := range varNames {
		value, found := os.LookupEnv(varName)
		if !found {
			return nil, fmt.Errorf("%s environment variable not set", varName)
		}
		data, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 environment variable '%s': %v", varName, err)
		}
		envVars[varName] = string(data)
	}
	return envVars, nil
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
