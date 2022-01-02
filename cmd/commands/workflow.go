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
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	"github.com/juju/ansiterm"

	"github.com/spf13/cobra"
)

func NewWorkflowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "workflow",
		Short:             "Manage workflows of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewWorkflowGetCommand())
	cmd.AddCommand(NewWorkflowListCommand())

	return cmd
}

func NewWorkflowGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [uid]",
		Short: "Get a workflow under a specific uid",
		Example: util.Doc(`
			<BIN> workflow get 0732b138-b74c-4a5e-b065-e23e6da0803d
		`),
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.G(cmd.Context()).Fatal("must enter uid")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			return RunWorkflowGet(ctx, args[0])
		},
	}

	return cmd
}

func NewWorkflowListCommand() *cobra.Command {
	var (
		namespace string
		runtime   string
		project   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all the workflows",
		Example: util.Doc(`
			<BIN> workflows list

			<BIN> workflows list --runtime <runtime>

			<BIN> workflows list -r <runtime>
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			filterArgs := model.WorkflowsFilterArgs{
				Namespace: &namespace,
				Runtime:   &runtime,
				Project:   &project,
			}
			return RunWorkflowList(ctx, filterArgs)
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "N", "", "Filter by workflow namespace")
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Filter by workflow runtime")
	cmd.Flags().StringVarP(&project, "project", "p", "", "Filter by workflow project")

	return cmd
}

func RunWorkflowGet(ctx context.Context, uid string) error {
	workflow, err := cfConfig.NewClient().V2().Workflow().Get(ctx, uid)
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

func RunWorkflowList(ctx context.Context, filterArgs model.WorkflowsFilterArgs) error {
	workflows, err := cfConfig.NewClient().V2().Workflow().List(ctx, filterArgs)
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
