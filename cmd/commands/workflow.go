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
	"fmt"
	"os"

	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/util"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
)

func newWorkflowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "workflow",
		Short:             "Manage workflows of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(newWorkflowGetCommand())
	cmd.AddCommand(newWorkflowListCommand())

	return cmd
}

func newWorkflowGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get UID",
		Args:  cobra.MaximumNArgs(1),
		Short: "Get a workflow under a specific uid",
		Example: util.Doc(`
			<BIN> workflow get 0732b138-b74c-4a5e-b065-e23e6da0803d
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) < 1 {
				return fmt.Errorf("must enter uid")
			}

			return runWorkflowGet(ctx, args[0])
		},
	}

	return cmd
}

func newWorkflowListCommand() *cobra.Command {
	var (
		namespace string
		runtime   string
		project   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all the workflows",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
			<BIN> workflows list

			<BIN> workflows list --runtime <runtime>

			<BIN> workflows list -r <runtime>
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			filterArgs := platmodel.WorkflowsFilterArgs{
				Namespace: &namespace,
				Runtime:   &runtime,
				Project:   &project,
			}
			return runWorkflowList(ctx, filterArgs)
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "N", "", "Filter by workflow namespace")
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Filter by workflow runtime")
	cmd.Flags().StringVarP(&project, "project", "p", "", "Filter by workflow project")

	return cmd
}

func runWorkflowGet(ctx context.Context, uid string) error {
	workflow, err := cfConfig.NewClient().GraphQL().Workflow().Get(ctx, uid)
	if err != nil {
		return err
	}

	if workflow == nil {
		log.G(ctx).WithField("uid", uid).Warn("workflow was not found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE\tUID")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
		workflow.Metadata.Name,
		*workflow.Metadata.Namespace,
		workflow.Metadata.Runtime,
		workflow.Status.Phase,
		*workflow.Metadata.UID,
	)
	if err != nil {
		return err
	}

	return tb.Flush()
}

func runWorkflowList(ctx context.Context, filterArgs platmodel.WorkflowsFilterArgs) error {
	workflows, err := cfConfig.NewClient().GraphQL().Workflow().List(ctx, filterArgs)
	if err != nil {
		return err
	}

	if len(workflows) == 0 {
		log.G(ctx).Warn("no workflows were found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE\tUID")
	if err != nil {
		return err
	}

	for _, w := range workflows {
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			w.Metadata.Name,
			*w.Metadata.Namespace,
			w.Metadata.Runtime,
			w.Status.Phase,
			*w.Metadata.UID,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
