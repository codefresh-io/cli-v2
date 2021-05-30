package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
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
	cmd.AddCommand(NewAuthUseContextCommand())
	cmd.AddCommand(NewAuthCreateContextCommand())
	cmd.AddCommand(NewAuthDeleteContextCommand())

	return cmd
}

func NewAuthCreateContextCommand() *cobra.Command {
	var (
		apiKey string
		url    string
	)

	cmd := &cobra.Command{
		Use:   "create-context",
		Short: "Create a new Codefresh authentication context",
		Example: util.Doc(`
# Create a new context named 'test':

		<BIN> auth create-context test --api-key TOKEN`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}
			return RunAuthCreateContext(cmd.Context(), args[0], apiKey, url)
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key")
	cmd.Flags().StringVar(&url, "url", store.Get().DefaultAPI, "Codefresh system custom url ")
	die(cmd.MarkFlagRequired("api-key"))

	return cmd
}

func RunAuthCreateContext(ctx context.Context, context, apiKey, url string) error {
	if err := cfConfig.NewContext(ctx, context, apiKey, url); err != nil {
		return err
	}
	log.G().Infof("create new context: %s", context)
	return RunAuthUseContext(ctx, context)
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

func NewAuthUseContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use-context CONTEXT",
		Short: "Switch the current authentication context",
		Example: util.Doc(`
# Switch to another authentication context:

		<BIN> auth use-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}
			return RunAuthUseContext(cmd.Context(), args[0])
		},
	}

	return cmd
}

func RunAuthUseContext(ctx context.Context, context string) error {
	if err := cfConfig.UseContext(ctx, context); err != nil {
		return err
	}
	log.G().Infof("switched to context: %s", context)
	return nil
}

func NewAuthDeleteContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete-context CONTEXT",
		Short: "Delete the specified authentication context",
		Example: util.Doc(`
# Deleting an authentication context name 'test':

		<BIN> auth delete-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}
			return RunAuthDeleteContext(cmd.Context(), args[0])
		},
	}

	return cmd
}

func RunAuthDeleteContext(ctx context.Context, context string) error {
	if err := cfConfig.DeleteContext(context); err != nil {
		return err
	}
	log.G().Infof("delete context: %s", context)
	return nil
}
