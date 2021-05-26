package main

import (
	"context"
	"syscall"

	"github.com/codefresh-io/cli-v2/cmd/commands"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/sirupsen/logrus"
)

//go:generate sh -c "echo  generating command docs... && cd .. && go run ./hack/cmd-docs/main.go"

func main() {
	ctx := context.Background()
	lgr := log.FromLogrus(logrus.NewEntry(logrus.New()), &log.LogrusConfig{Level: "info"})
	ctx = log.WithLogger(ctx, lgr)
	ctx = util.ContextWithCancelOnSignals(ctx, syscall.SIGINT, syscall.SIGTERM)

	c := commands.NewRoot()
	lgr.AddPFlags(c)

	if err := c.ExecuteContext(ctx); err != nil {
		log.G(ctx).Fatal(err)
	}
}
