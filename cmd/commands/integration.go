package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
	sdk "github.com/codefresh-io/go-sdk/pkg/codefresh"
	model "github.com/codefresh-io/go-sdk/pkg/codefresh/model/app-proxy"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
)

type (
	GitIntegrationAddOptions struct {
		Name          string
		Provider      model.GitProviders
		SharingPolicy model.SharingPolicy
	}
)

func NewIntegrationCommand() *cobra.Command {
	var (
		runtime string
		client  sdk.AppProxyAPI
	)

	cmd := &cobra.Command{
		Use:               "integration",
		Aliases:           []string{"integrations", "intg"},
		Short:             "Manage integrations with git providers, container registries and more",
		PersistentPreRunE: getAppProxyClient(&runtime, &client),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.PersistentFlags().StringVar(&runtime, "runtime", "", "Name of runtime to use")

	cmd.AddCommand(NewGitIntegrationCommand(&client))

	return cmd
}

func NewGitIntegrationCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Manage your git integrations",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewGitIntegrationListCommand(client))
	cmd.AddCommand(NewGitIntegrationAddCommand(client))
	cmd.AddCommand(NewGitIntegrationEditCommand(client))
	cmd.AddCommand(NewGitIntegrationRemoveCommand(client))
	cmd.AddCommand(NewGitIntegrationRegisterCommand(client))
	cmd.AddCommand(NewGitIntegrationDeregisterCommand(client))

	return cmd
}

func NewGitIntegrationListCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *client)
		},
	}

	return cmd
}

func RunGitIntegrationListCommand(ctx context.Context, client sdk.AppProxyAPI) error {
	integrations, err := client.GitIntegrations().List(ctx)
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

func NewGitIntegrationAddCommand(client *sdk.AppProxyAPI) *cobra.Command {
	var (
		opts              model.AddGitIntegrationArgs
		provider          string
		accountAdminsOnly bool
	)

	providers := map[string]model.GitProviders{
		"github": model.GitProvidersGithub,
		"gitlab": model.GitProvidersGitlab,
	}

	cmd := &cobra.Command{
		Use:   "add NAME",
		Short: "Add a new git integration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("missing integration name")
			}

			opts.Name = args[0]

			p, ok := providers[provider]
			if !ok {
				return fmt.Errorf("provider '%s' is not a valid provider name", provider)
			}
			opts.Provider = p

			opts.SharingPolicy = model.SharingPolicyAllUsersInAccount
			if accountAdminsOnly {
				opts.SharingPolicy = model.SharingPolicyAccountAdmins
			}

			return RunGitIntegrationAddCommand(cmd.Context(), *client, &opts)
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "github", "One of github|gitlab")
	cmd.Flags().StringVar(&opts.APIURL, "api-url", "", "Git provider API Url")
	cmd.Flags().BoolVar(&accountAdminsOnly, "account-admins-only", false, "If true, this integration would only be visible to account admins")

	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "api-url"))

	return cmd
}

func RunGitIntegrationAddCommand(ctx context.Context, client sdk.AppProxyAPI, opts *model.AddGitIntegrationArgs) error {
	intg, err := client.GitIntegrations().Add(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to add git integration: %w", err)
	}

	log.G(ctx).Infof("created git integration: %s", intg.Name)

	return nil
}

func NewGitIntegrationEditCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *client)
		},
	}

	return cmd
}

func NewGitIntegrationRemoveCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *client)
		},
	}

	return cmd
}

func NewGitIntegrationRegisterCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *client)
		},
	}

	return cmd
}

func NewGitIntegrationDeregisterCommand(client *sdk.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitIntegrationListCommand(cmd.Context(), *client)
		},
	}

	return cmd
}

func getAppProxyClient(runtime *string, client *sdk.AppProxyAPI) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := cfConfig.RequireAuthentication(cmd, args); err != nil {
			return err
		}

		if *runtime != "" {
			return nil
		}

		cur := cfConfig.GetCurrentContext()

		if cur.DefaultRuntime == "" {
			return fmt.Errorf("missing name of runtime to use")
		}

		*runtime = cur.DefaultRuntime

		appProxy, err := cfConfig.NewClient().AppProxy(cmd.Context(), *runtime)
		if err != nil {
			return err
		}

		*client = appProxy

		return nil
	}
}
