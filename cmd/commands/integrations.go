// Copyright 2025 The Codefresh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	ap "github.com/codefresh-io/go-sdk/pkg/appproxy"
	apmodel "github.com/codefresh-io/go-sdk/pkg/model/app-proxy"
	"github.com/ghodss/yaml"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type (
	GitIntegrationAddOptions struct {
		Name          string
		Provider      apmodel.GitProviders
		SharingPolicy apmodel.SharingPolicy
	}

	GitIntegrationRegistrationOpts struct {
		Name     string
		Token    string
		Username string
	}
)

var cliToModelMap = map[string]string{
	string(cfgit.BITBUCKET):        apmodel.GitProvidersBitbucket.String(),
	string(cfgit.BITBUCKET_SERVER): apmodel.GitProvidersBitbucketServer.String(),
	string(cfgit.GITHUB):           apmodel.GitProvidersGithub.String(),
	string(cfgit.GITLAB):           apmodel.GitProvidersGitlab.String(),
}

var modelToCliMap = util.ReverseMap(cliToModelMap)

func NewIntegrationCommand() *cobra.Command {
	var (
		runtime  string
		apClient ap.AppProxyAPI
	)

	cmd := &cobra.Command{
		Use:               "integration",
		Aliases:           []string{"integrations", "intg"},
		Short:             "Manage integrations with git providers, container registries and more",
		PersistentPreRunE: getAppProxyClient(&runtime, &apClient),
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.PersistentFlags().StringVar(&runtime, "runtime", "", "Name of runtime to use")

	cmd.AddCommand(NewGitIntegrationCommand(&apClient))

	return cmd
}

func NewGitIntegrationCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Manage your git integrations",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewGitIntegrationListCommand(apClient))
	cmd.AddCommand(NewGitIntegrationGetCommand(apClient))
	cmd.AddCommand(NewGitIntegrationAddCommand(apClient))
	cmd.AddCommand(NewGitIntegrationEditCommand(apClient))
	cmd.AddCommand(NewGitIntegrationRemoveCommand(apClient))
	cmd.AddCommand(NewGitIntegrationRegisterCommand(apClient))
	cmd.AddCommand(NewGitIntegrationDeregisterCommand(apClient))
	cmd.AddCommand(NewGitAuthCommand())

	return cmd
}

func NewGitIntegrationListCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	var format string

	allowedFormats := []string{"list", "yaml", "yml", "json"}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your git integrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := verifyOutputFormat(format, allowedFormats...); err != nil {
				return err
			}

			return RunGitIntegrationListCommand(cmd.Context(), *apClient, format)
		},
	}

	cmd.Flags().StringVarP(&format, "output", "o", "list", "Output format, one of: "+strings.Join(allowedFormats, "|"))

	return cmd
}

func RunGitIntegrationListCommand(ctx context.Context, apClient ap.AppProxyAPI, format string) error {
	integrations, err := apClient.GitIntegration().List(ctx)
	if err != nil {
		return err
	}

	if format == "list" {
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
				len(intg.Users),
				intg.SharingPolicy.String(),
			)
			if err != nil {
				return err
			}
		}

		return tb.Flush()
	}

	return printIntegration(integrations, format)
}

func NewGitIntegrationGetCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	var (
		format      string
		integration *string
	)

	allowedFormats := []string{"yaml", "yml", "json"}

	cmd := &cobra.Command{
		Use:   "get [NAME]",
		Short: "Retrieve a git integration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				integration = &args[0]
			}

			if err := verifyOutputFormat(format, allowedFormats...); err != nil {
				return err
			}

			return RunGitIntegrationGetCommand(cmd.Context(), *apClient, integration, format)
		},
	}

	cmd.Flags().StringVarP(&format, "output", "o", "yaml", "Output format, one of: "+strings.Join(allowedFormats, "|"))

	return cmd
}

func RunGitIntegrationGetCommand(ctx context.Context, apClient ap.AppProxyAPI, name *string, format string) error {
	gi, err := apClient.GitIntegration().Get(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get git integration: %w", err)
	}

	return printIntegration(gi, format)
}

func NewGitIntegrationAddCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	var (
		opts              apmodel.AddGitIntegrationArgs
		provider          string
		apiURL            string
		accountAdminsOnly bool
	)

	cmd := &cobra.Command{
		Use:   "add [NAME]",
		Short: "Add a new git integration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			if len(args) > 0 {
				opts.Name = &args[0]
			}

			opts.APIURL = &apiURL

			if opts.Provider, err = cliToModelGitProvider(provider); err != nil {
				return err
			}

			opts.SharingPolicy = apmodel.SharingPolicyAllUsersInAccount
			if accountAdminsOnly {
				opts.SharingPolicy = apmodel.SharingPolicyAccountAdmins
			}

			return RunGitIntegrationAddCommand(cmd.Context(), *apClient, &opts)
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "github", "One of bitbucket|bitbucket-server|github|gitlab")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Git provider API Url")
	cmd.Flags().BoolVar(&accountAdminsOnly, "account-admins-only", false,
		"If true, this integration would only be visible to account admins (default: false)")

	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "api-url"))

	return cmd
}

func RunGitIntegrationAddCommand(ctx context.Context, apClient ap.AppProxyAPI, opts *apmodel.AddGitIntegrationArgs) error {
	intg, err := apClient.GitIntegration().Add(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to add git integration: %w", err)
	}

	log.G(ctx).Infof("created git integration: %s", intg.Name)

	return nil
}

func NewGitIntegrationEditCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	var (
		opts              apmodel.EditGitIntegrationArgs
		apiURL            string
		accountAdminsOnly bool
	)

	cmd := &cobra.Command{
		Use:   "edit [NAME]",
		Short: "Edit a git integration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Name = &args[0]
			}

			opts.APIURL = &apiURL

			opts.SharingPolicy = apmodel.SharingPolicyAllUsersInAccount
			if accountAdminsOnly {
				opts.SharingPolicy = apmodel.SharingPolicyAccountAdmins
			}

			return RunGitIntegrationEditCommand(cmd.Context(), *apClient, &opts)
		},
	}

	cmd.Flags().StringVar(&apiURL, "api-url", "", "Git provider API Url")
	cmd.Flags().BoolVar(&accountAdminsOnly, "account-admins-only", false,
		"If true, this integration would only be visible to account admins (default: false)")

	return cmd
}

func RunGitIntegrationEditCommand(ctx context.Context, apClient ap.AppProxyAPI, opts *apmodel.EditGitIntegrationArgs) error {
	intg, err := apClient.GitIntegration().Edit(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to edit git integration: %w", err)
	}

	log.G(ctx).Infof("edited git integration: %s", intg.Name)

	return nil
}

func NewGitIntegrationRemoveCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove a git integration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("missing integration name")
			}

			return RunGitIntegrationRemoveCommand(cmd.Context(), *apClient, args[0])
		},
	}

	return cmd
}

func RunGitIntegrationRemoveCommand(ctx context.Context, apClient ap.AppProxyAPI, name string) error {
	if err := apClient.GitIntegration().Remove(ctx, name); err != nil {
		return fmt.Errorf("failed to remove git integration: %w", err)
	}

	log.G(ctx).Infof("Removed git integration: %s", name)

	return nil
}

func NewGitIntegrationRegisterCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	opts := &GitIntegrationRegistrationOpts{}
	cmd := &cobra.Command{
		Use:   "register [NAME]",
		Short: "Register to a git integrations",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Name = args[0]
			}

			return RunGitIntegrationRegisterCommand(cmd.Context(), *apClient, opts)
		},
	}

	util.Die(viper.BindEnv("token", "GIT_TOKEN"))
	cmd.Flags().StringVar(&opts.Token, "token", "", "Authentication token")

	util.Die(viper.BindEnv("username", "GIT_USER"))

	cmd.Flags().StringVar(&opts.Username, "username", "", "Authentication user name")

	util.Die(cmd.MarkFlagRequired("token"))

	return cmd
}

func RunGitIntegrationRegisterCommand(ctx context.Context, apClient ap.AppProxyAPI, opts *GitIntegrationRegistrationOpts) error {
	regOpts := &apmodel.RegisterToGitIntegrationArgs{
		Token: opts.Token,
	}
	if opts.Username != "" {
		regOpts.Username = &opts.Username
	}

	if opts.Name != "" {
		regOpts.Name = &opts.Name
	}

	intg, err := apClient.GitIntegration().Register(ctx, regOpts)
	if err != nil {
		return fmt.Errorf("failed to register to git integration: %w", err)
	}

	log.G(ctx).Infof("registered to git integration: %s", intg.Name)

	return nil
}

func NewGitIntegrationDeregisterCommand(apClient *ap.AppProxyAPI) *cobra.Command {
	var integration *string

	cmd := &cobra.Command{
		Use:   "deregister [NAME]",
		Short: "Deregister user from a git integrations",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				integration = &args[0]
			}

			return RunGitIntegrationDeregisterCommand(cmd.Context(), *apClient, integration)
		},
	}

	return cmd
}

func RunGitIntegrationDeregisterCommand(ctx context.Context, apClient ap.AppProxyAPI, name *string) error {
	gi, err := apClient.GitIntegration().Deregister(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to deregister user from git integration: %w", err)
	}

	log.G(ctx).Infof("deregistered user from git integration: %s", gi.Name)

	return nil
}

func getAppProxyClient(runtime *string, apClient *ap.AppProxyAPI) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := cfConfig.RequireAuthentication(cmd, args); err != nil {
			return err
		}

		if *runtime == "" {
			cur := cfConfig.GetCurrentContext()

			if cur.DefaultRuntime == "" {
				return fmt.Errorf("default runtime not set, you must specify the runtime name with --runtime")
			}

			*runtime = cur.DefaultRuntime
		}

		appProxy, err := cfConfig.NewClient().AppProxy(cmd.Context(), *runtime, store.Get().InsecureIngressHost)
		if err != nil {
			return err
		}

		*apClient = appProxy
		return nil
	}
}

func NewGitAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGitAuthCommand(cmd.Context(), cmd)
		},
	}

	return cmd
}

func RunGitAuthCommand(ctx context.Context, cmd *cobra.Command) error {
	var err error
	user, err := cfConfig.GetUser(ctx)
	if err != nil {
		return err
	}

	accountId, err := util.CurrentAccount(user)
	if err != nil {
		return err
	}

	runtimeName := cmd.Flag("runtime").Value.String()
	runtime, err := getRuntime(ctx, runtimeName)
	if err != nil {
		return err
	}

	return util.OpenBrowserForGitLogin(*runtime.IngressHost, user.ID, accountId)
}

func printIntegration(i interface{}, format string) error {
	var (
		data []byte
		err  error
	)
	switch format {
	case "json":
		data, err = json.Marshal(i)
	case "yaml", "yml":
		data, err = yaml.Marshal(i)
	default:
		return fmt.Errorf("invalid output format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal integration: %w", err)
	}
	fmt.Println(string(data))

	return nil
}

func verifyOutputFormat(format string, allowedFormats ...string) error {
	for _, f := range allowedFormats {
		if format == f {
			return nil
		}
	}

	return fmt.Errorf("invalid output format: %s", format)
}

// cliToModelGitProvider converts cli lowercase provider string (bitbucket|bitbucket-server|github|gitlab)
// to model uppercase provider string (BITBUCKET|BITBUCKET_SERVER|GITHUB|GITLAB)
func cliToModelGitProvider(provider string) (apmodel.GitProviders, error) {
	p, ok := cliToModelMap[provider]
	if !ok {
		return apmodel.GitProviders(""), fmt.Errorf("provider \"%s\" is not a valid provider name", provider)
	}

	return apmodel.GitProviders(p), nil
}

// modelToCliGitProvider converts model uppercase provider string (BITBUCKET|BITBUCKET_SERVER|GITHUB|GITLAB)
// to cli lowercase provider string (bitbucket|bitbucket-server|github|gitlab)
func modelToCliGitProvider(provider string) (cfgit.ProviderType, error) {
	p, ok := modelToCliMap[provider]
	if !ok {
		return cfgit.ProviderType(""), fmt.Errorf("provider \"%s\" is not a valid provider name", provider)
	}

	return cfgit.ProviderType(p), nil
}
