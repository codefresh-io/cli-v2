package commands

import (
	"context"

	"github.com/codefresh-io/cli-v2/pkg/util"

	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/spf13/cobra"
)

type (
	RuntimeCreateOptions struct{}
)

func NewRuntimeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Manage Codefresh runtimes",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewRuntimeCreateCommand())

	return cmd
}

func NewRuntimeCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Codefresh runtime",
		Example: util.Doc(`
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunRuntimeCreate(cmd.Context(), &RuntimeCreateOptions{})
		},
	}

	return cmd
}

func RunRuntimeCreate(ctx context.Context, opts *RuntimeCreateOptions) error {
	err := apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		
	})
	// autopilot repo create --owner --name -> cloneUrl
	// 					 repo bootstrap --repo --app
	//           project create codefresh
	//           app create workflows --app
	//           app create events --app
	//           app create rollouts --app
	return err
}
