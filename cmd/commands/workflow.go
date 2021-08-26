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
		Use:   "get [runtime_name]",
		Short: "Get a workflow under a specific runtime",
		Example: util.Doc(`
			<BIN> workflow get runtime_name
		`),
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) < 3 {
				log.G(cmd.Context()).Fatal("must enter runtime name")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunWorkflowGet(ctx, args[0], args[1], args[2])
		},
	}

	return cmd
}

func NewWorkflowListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		//Use:   "list [runtime_name]",
		Short: "List all the workflows under a specific runtime",
		Example: util.Doc(`
			<BIN> workflows list runtime_name
		`),
		//PreRun: func(cmd *cobra.Command, args []string) {
		//	if len(args) < 1 {
		//		log.G(cmd.Context()).Fatal("must enter runtime name")
		//	}
		//},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunWorkflowList(ctx)
		},
	}

	return cmd
}

func RunWorkflowGet(ctx context.Context, name, namespace, runtime string) error {
	workflow, err := cfConfig.NewClient().V2().Workflow().Get(ctx, name, namespace, runtime)
	if err != nil {
		return err
	}

	if workflow == nil {
		log.G(ctx).WithField("runtime", runtime).Warn("workflow was not found in runtime")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	//_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE\tSTARTED AT\tFINISHED AT")
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE")
	if err != nil {
		return err
	}

	//uid := w.Metadata.UID
	_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\n",
		workflow.Metadata.Name,
		*workflow.Metadata.Namespace,
		workflow.Metadata.Runtime,
		workflow.Status.Phase.String(),
		//*w.Status.StartedAt,
		//*w.Status.FinishedAt,
	)
	if err != nil {
		return err
	}

	return tb.Flush()
}

func RunWorkflowList(ctx context.Context) error {
	workflows, err := cfConfig.NewClient().V2().Workflow().List(ctx, model.WorkflowsFilterArgs{})
	if err != nil {
		return err
	}

	if len(workflows) == 0 {
		log.G(ctx).Warn("no workflows were found")
		//log.G(ctx).WithField("runtime", runtime).Warn("no workflows were found in runtime")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	//_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE\tSTARTED AT\tFINISHED AT")
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tPHASE")
	if err != nil {
		return err
	}

	for _, w := range workflows {
		//uid := w.Metadata.UID
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\n",
			w.Metadata.Name,
			*w.Metadata.Namespace,
			w.Metadata.Runtime,
			w.Status.Phase.String(),
			//*w.Status.StartedAt,
			//*w.Status.FinishedAt,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
