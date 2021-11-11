package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
)

func NewIntegrationCommand() *cobra.Command {
	var (
		runtime string
	)

	cmd := &cobra.Command{
		Use:     "integration",
		Aliases: []string{"integrations", "intg"},
		Short:   "Manage integrations with git providers, container registries and more",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := cfConfig.RequireAuthentication(cmd, args); err != nil {
				return err
			}

			if runtime != "" {
				return nil
			}

			cur := cfConfig.GetCurrentContext()

			if cur.DefaultRuntime == "" {
				return fmt.Errorf("missing name of runtime to use")
			}

			runtime = cur.DefaultRuntime

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.PersistentFlags().StringVar(&runtime, "runtime", "", "Name of runtime to use")

	cmd.AddCommand(NewGitIntegrationCommand(&runtime))

	return cmd
}

func NewGitIntegrationCommand(runtime *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Manage your git integrations",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewGitIntegrationListCommand(runtime))

	return cmd
}

func NewGitIntegrationListCommand(runtime *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *runtime)
		},
	}

	return cmd
}

func RunGitIntegrationListCommand(ctx context.Context, runtime string) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, runtime)
	if err != nil {
		return err
	}

	integrations, err := appProxy.GitIntegrations().List(ctx)
	if err != nil {
		return err
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tPROVIDER\tAPI URL\tREGISTERED USERS\tSHARING POLICY")
	if err != nil {
		return err
	}

	for _, intg := range integrations {
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%d\t%s\n",
			intg.Name,
			intg.Provider,
			intg.APIURL,
			len(intg.RegisteredUsers),
			intg.SharingPolicy.String(),
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
