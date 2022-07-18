package vsdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/FlowFabricator/vector-plugins/plugins"
	"github.com/FlowFabricator/vector-plugins/states"
	"github.com/FlowFabricator/vector-sdk/sdkpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	tlsConf, err := decodeTLSConf(envVars["API_TLS_CONF"])
	if err != nil {
		return states.ActionOutput{}, fmt.Errorf("failed to decode TLS config: %v", err)
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
		grpc.WithPerRPCCredentials(&authenticator{apiToken: envVars["API_TOKEN"]}),
		grpc.WithBlock(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := grpc.DialContext(ctx, envVars["API_SERVER_URL"], dialOpts...)
	cancel()
	if err != nil {
		return states.ActionOutput{}, err
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
		Roles: roles,
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
	varNames := []string{"STATE_NAME", "EXEC_ID", "API_SERVER_URL", "API_TOKEN", "API_TLS_CONF"}
	envVars := make(map[string]string)
	for _, varName := range varNames {
		value, found := os.LookupEnv(varName)
		if !found {
			return nil, fmt.Errorf("%s environment variable not set", varName)
		}
		envVars[varName] = value
	}
	return envVars, nil
}

func decodeTLSConf(encodedTlsConf string) (*tls.Config, error) {
	conf := &tls.Config{}
	dec := gob.NewDecoder(bytes.NewReader([]byte(encodedTlsConf)))
	if err := dec.Decode(conf); err != nil {
		return nil, err
	}
	return conf, nil
}
