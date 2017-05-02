package util

import (
	"github.com/TheThingsNetwork/ttn/core"
	"github.com/TheThingsNetwork/ttn/core/components/handler"
	"github.com/apex/log"
)

var ttnHandler = "localhost:1782"

func GetHandlerManager(ctx log.Interface) core.AuthHandlerClient {
	cli, err := handler.NewClient(ttnHandler)
	if err != nil {
		ctx.Fatalf("Could not connect: %v", err)
	}
	return cli
}
