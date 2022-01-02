// Copyright 2022 The Codefresh Authors.
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

// Copyright 2021 The Codefresh Authors.
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
	"fmt"
	"os"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/spf13/cobra"
)

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config",
		Short:             "Manage Codefresh authentication contexts",
		PersistentPreRunE: cfConfig.Load,
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

	return cmd
}

func NewConfigCreateContextCommand() *cobra.Command {
	var (
		apiKey string
		url    string
	)

	cmd := &cobra.Command{
		Use:   "create-context",
		Short: "Create a new Codefresh authentication context",
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
	log.G().Infof("New context created: '%s'", context)
	return RunConfigUseContext(ctx, context)
}

func NewConfigGetContextsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get-contexts",
		Aliases: []string{"view"},
		Short:   "Lists all Codefresh authentication contexts",
		Example: util.Doc(`
# List all authentication contexts:

		<BIN> config get-contexts`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunConfigGetContexts(cmd.Context())
		},
	}

	return cmd
}

func RunConfigGetContexts(ctx context.Context) error {
	return cfConfig.Write(ctx, os.Stdout)
}

func NewConfigCurrentContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "current-context",
		Short: "Shows the currently selected Codefresh authentication context",
		Example: util.Doc(`
# Shows the current context:

		<BIN> config current-context`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunConfigCurrentContext(cmd.Context())
		},
	}

	return cmd
}

func RunConfigCurrentContext(ctx context.Context) error {
	cur := cfConfig.GetCurrentContext()
	if cur.Name == "" {
		log.G(ctx).Fatal(util.Doc("no currently selected context, use '<BIN> config use-context' to select a context"))
	}

	log.G(ctx).Info(cur.Name)
	return nil
}

func NewConfigSetRuntimeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-runtime RUNTIME",
		Short: "Sets the default runtime name to use for the current authentication context",
		Example: util.Doc(`
# Sets the default runtime to 'runtime-2':

		<BIN> config set-runtime runtime-2`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide runtime name to use")

			}

			return RunConfigSetRuntime(cmd.Context(), args[0])
		},
	}

	return cmd
}

func RunConfigSetRuntime(ctx context.Context, runtime string) error {
	_, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtime)
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
	cmd := &cobra.Command{
		Use:   "get-runtime",
		Short: "Gets the default runtime for the current authentication context",
		Example: util.Doc(`
# Prints the default runtime:

		<BIN> config get-runtime`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunConfigGetRuntime(cmd.Context())
		},
	}

	return cmd
}

func RunConfigGetRuntime(ctx context.Context) error {
	cur := cfConfig.GetCurrentContext()
	if cur.DefaultRuntime == "" {
		return fmt.Errorf(util.Doc("no default runtime is set for current context, use '<BIN> config set-runtime' to set one"))
	}

	log.G(ctx).Infof("default runtime set to: %s", cur.DefaultRuntime)

	return nil
}

func NewConfigUseContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use-context CONTEXT",
		Short: "Switch the current authentication context",
		Example: util.Doc(`
# Switch to another authentication context:

		<BIN> config use-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}
			return RunConfigUseContext(cmd.Context(), args[0])
		},
	}

	return cmd
}

func RunConfigUseContext(ctx context.Context, context string) error {
	if err := cfConfig.UseContext(ctx, context); err != nil {
		return err
	}
	log.G().Infof("Switched to context: %s", context)
	return nil
}

func NewConfigDeleteContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete-context CONTEXT",
		Short: "Delete the specified authentication context",
		Example: util.Doc(`
# Deleting an authentication context name 'test':

		<BIN> config delete-context test`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must provide context name to use")
			}
			return RunConfigDeleteContext(cmd.Context(), args[0])
		},
	}

	return cmd
}

func RunConfigDeleteContext(ctx context.Context, context string) error {
	if err := cfConfig.DeleteContext(context); err != nil {
		return err
	}

	log.G(ctx).Infof("Deleted context: %s", context)
	return nil
}
