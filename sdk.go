package vsdk

import (
	"context"
	"encoding/json"
	"github.com/FlowFabricator/vector-plugins/plugins"
	"github.com/FlowFabricator/vector-plugins/states"
	"github.com/FlowFabricator/vector-sdk/sdkpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"time"
)

func Call(pluginName, action string, args plugins.Args) (states.ActionOutput, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := grpc.DialContext(ctx, "localhost:9260", dialOpts...)
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
		Plugin:        pluginName,
		PluginVersion: "v0.1.0",
		Action:        action,
		ArgsMapAsJson: argsAsJson,
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
