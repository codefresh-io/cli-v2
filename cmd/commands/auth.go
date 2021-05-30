package commands

import (
	"context"
	"os"

	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/spf13/cobra"
)

func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage Codefresh authentication contexts",
		Long: util.Doc(`By default, <BIN> authentication contexts are persisted at $HOME/.cfconfig.
You can create, delete and list authentication contexts using the following
commands, respectively:

		<BIN> auth create-context <NAME> --api-key <key>

		<BIN> auth delete-context <NAME>

		<BIN> auth get-contexts
`),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewAuthGetContextsCommand())

	return cmd
}

func NewAuthGetContextsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get-contexts",
		Aliases: []string{"view"},
		Short:   "Lists all Codefresh authentication contexts",
		Example: util.Doc(`
# List all authentication contexts:

		<BIN> auth get-contexts`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAuthGetContexts(cmd.Context())
		},
	}

	return cmd
}

func RunAuthGetContexts(ctx context.Context) error {
	return cfConfig.Write(ctx, os.Stdout)
}
