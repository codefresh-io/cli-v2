// Copyright 2023 The Codefresh Authors.
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
	"errors"
	"fmt"
	"os"
	"strings"

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

type (
	updateCsdpSettingsOpts struct {
		gitProvider      cfgit.ProviderType
		gitApiUrl        string
		sharedConfigRepo string
	}
)

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config",
		Short:             "Manage Codefresh authentication contexts",
		PersistentPreRunE: cfConfig.Load,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Long: util.Doc(`By default, Codefresh authentication contexts are persisted at $HOME/.cfconfig.
You can create, delete and list authentication contexts using the following
commands, respectively:

		<BIN> config create-context <NAME> --api-key <key>

		<BIN> config delete-context <NAME>

		<BIN> config get-contexts
`),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewConfigGetContextsCommand())
	cmd.AddCommand(NewConfigCurrentContextCommand())
	cmd.AddCommand(NewConfigUseContextCommand())
	cmd.AddCommand(NewConfigCreateContextCommand())
	cmd.AddCommand(NewConfigDeleteContextCommand())
	cmd.AddCommand(NewConfigSetRuntimeCommand())
	cmd.AddCommand(NewConfigGetRuntimeCommand())
	cmd.AddCommand(NewResetIscRepoUrlCommand())
	cmd.AddCommand(NewUpdateCsdpSettingsCommand())

	return cmd
}

func NewConfigCreateContextCommand() *cobra.Command {
	var (
		apiKey string
		url    string
	)

	cmd := &cobra.Command{
		Use:   "create-context NAME",
		Short: "Create a new Codefresh authentication context",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# Create a new context named 'test':

		<BIN> config create-context test --api-key TOKEN`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}

			return RunConfigCreateContext(cmd.Context(), args[0], apiKey, url)
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key")
	cmd.Flags().StringVar(&url, "url", store.Get().DefaultAPI, "Codefresh system custom url ")
	die(cmd.MarkFlagRequired("api-key"))

	return cmd
}

func RunConfigCreateContext(ctx context.Context, context, apiKey, url string) error {
	if err := cfConfig.CreateContext(ctx, context, apiKey, url); err != nil {
		return err
	}

	log.G().Infof("New context created: \"%s\"", context)
	return runConfigUseContext(ctx, context)
}

func NewConfigGetContextsCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "get-contexts",
		Aliases: []string{"view"},
		Args:    cobra.NoArgs,
		Short:   "Lists all Codefresh authentication contexts",
		Example: util.Doc(`
# List all authentication contexts:

		<BIN> config get-contexts`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfigGetContexts(cmd.Context())
		},
	}
}

func runConfigGetContexts(ctx context.Context) error {
	return cfConfig.Write(ctx, os.Stdout)
}

func NewConfigCurrentContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "current-context",
		Short: "Shows the currently selected Codefresh authentication context",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
# Shows the current context:

		<BIN> config current-context`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfigCurrentContext(cmd.Context())
		},
	}
}

func runConfigCurrentContext(ctx context.Context) error {
	cur := cfConfig.GetCurrentContext()
	if cur.Name == "" {
		log.G(ctx).Fatal(util.Doc("no currently selected context, use '<BIN> config use-context' to select a context"))
	}

	log.G(ctx).Info(cur.Name)
	return nil
}

func NewConfigSetRuntimeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set-runtime RUNTIME",
		Short: "Sets the default runtime name to use for the current authentication context",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# Sets the default runtime to 'runtime-2':

		<BIN> config set-runtime runtime-2`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide runtime name to use")
			}

			return runConfigSetRuntime(cmd.Context(), args[0])
		},
	}
}

func runConfigSetRuntime(ctx context.Context, runtime string) error {
	_, err := getRuntime(ctx, runtime)
	if err != nil {
		return err
	}

	cur := cfConfig.GetCurrentContext()
	if cur.Name == "" {
		log.G(ctx).Fatal(util.Doc("no currently selected context, use '<BIN> config use-context' to select a context"))
	}

	cur.DefaultRuntime = runtime

	if err := cfConfig.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	log.G(ctx).Infof("default runtime set to: %s", runtime)

	return nil
}

func NewConfigGetRuntimeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get-runtime",
		Short: "Gets the default runtime for the current authentication context",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
# Prints the default runtime:

		<BIN> config get-runtime`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfigGetRuntime(cmd.Context())
		},
	}
}

func runConfigGetRuntime(ctx context.Context) error {
	cur := cfConfig.GetCurrentContext()
	if cur.DefaultRuntime == "" {
		return fmt.Errorf(util.Doc("no default runtime is set for current context, use '<BIN> config set-runtime' to set one"))
	}

	log.G(ctx).Infof("default runtime set to: %s", cur.DefaultRuntime)

	return nil
}

func NewConfigUseContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "use-context CONTEXT",
		Short: "Switch the current authentication context",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# Switch to another authentication context:

		<BIN> config use-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}

			return runConfigUseContext(cmd.Context(), args[0])
		},
	}
}

func runConfigUseContext(ctx context.Context, context string) error {
	if err := cfConfig.UseContext(ctx, context); err != nil {
		return err
	}
	log.G().Infof("Switched to context: %s", context)
	return nil
}

func NewConfigDeleteContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete-context CONTEXT",
		Short: "Delete the specified authentication context",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# Deleting an authentication context name 'test':

		<BIN> config delete-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}

			return runConfigDeleteContext(cmd.Context(), args[0])
		},
	}
}

func runConfigDeleteContext(ctx context.Context, context string) error {
	if err := cfConfig.DeleteContext(context); err != nil {
		return err
	}

	log.G(ctx).Infof("Deleted context: %s", context)
	return nil
}

func NewResetIscRepoUrlCommand() *cobra.Command {
	return &cobra.Command{
		Use:        "reset-shared-config-repo",
		Deprecated: "use update-csdp-settings command instead",
		Hidden:     true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return errors.New("command removed")
		},
	}
}

func runResetIscRepoUrl(ctx context.Context) error {
	err := cfConfig.NewClient().V2().Runtime().ResetSharedConfigRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to reset shared config repo. Error: %w", err)
	}

	return nil
}

func NewUpdateCsdpSettingsCommand() *cobra.Command {
	opts := &updateCsdpSettingsOpts{}
	cmd := &cobra.Command{
		Use:               "update-csdp-settings",
		Aliases:           []string{"update-csdp"},
		Short:             "Updates the account's CSDP settings (gitProvider|gitApiUrl|sharedConfigRepo) if possible",
		Args:              cobra.NoArgs,
		PersistentPreRunE: cfConfig.RequireAuthentication,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return updateCsdpSettingsPreRunHandler(opts)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdateCsdpSettings(cmd.Context(), opts)
		},
	}

	cmd.Flags().Var(&opts.gitProvider, "git-provider", "The git provider, one of: bitbucket|bitbucket-server|github|gitlab")
	cmd.Flags().StringVar(&opts.gitApiUrl, "git-api-url", "", "Your git server's API URL")
	cmd.Flags().StringVar(&opts.sharedConfigRepo, "shared-config-repo", "", "URL to the shared configurations repo")
	cmd.Flags().BoolVar(&store.Get().Silent, "silent", false, "Disables the command wizard")
	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "shared-config-repo"))

	return cmd
}

func updateCsdpSettingsPreRunHandler(opts *updateCsdpSettingsOpts) error {
	baseURL, _, _, _, _, _, _ := aputil.ParseGitUrl(opts.sharedConfigRepo)
	provider, err := cfgit.GetProvider(opts.gitProvider, baseURL, "")
	if err != nil {
		return err
	}

	if opts.gitProvider == "" {
		opts.gitProvider = provider.Type()
	}

	if opts.gitApiUrl == "" {
		opts.gitApiUrl = provider.ApiURL()
	} else if opts.gitApiUrl != provider.ApiURL() {
		return fmt.Errorf("supplied git-api-url \"%s\" does not match inferred git-api-url \"%s\" from shared-config-repo", opts.gitApiUrl, provider.ApiURL())
	}

	return nil
}

func runUpdateCsdpSettings(ctx context.Context, opts *updateCsdpSettingsOpts) error {
	apGitProvider, err := cliToModelGitProvider(string(opts.gitProvider))
	if err != nil {
		return err
	}

	platGitProvider := platmodel.GitProviders(apGitProvider)
	return cfConfig.NewClient().V2().AccountV2().UpdateCsdpSettings(ctx, platGitProvider, opts.gitApiUrl, opts.sharedConfigRepo)
}

func getGitApiUrlFromUserInput(def string) (string, error) {
	repoPrompt := promptui.Prompt{
		Label:   "Git API URL",
		Default: def,
		Validate: func(value string) error {
			if !strings.HasPrefix(value, "https://") {
				return fmt.Errorf("Invalid URL for Git API URL - must start with \"https://\"")
			}

			return nil
		},
	}
	return repoPrompt.Run()
}
