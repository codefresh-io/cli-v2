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

func NewPipelineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "pipeline",
		Short:             "Manage pipelines of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewPipelineGetCommand())
	cmd.AddCommand(NewPipelineListCommand())

	return cmd
}

func NewPipelineGetCommand() *cobra.Command {
	var (
		name string
		namespace string
		runtime string
	)

	cmd := &cobra.Command{
		Use:   "get [runtime_name]",
		Short: "Get a pipeline under a specific runtime",
		Example: util.Doc(`
			<BIN> pipeline get runtime_name
		`),
		PreRun: func(cmd *cobra.Command, args []string) {
			//if len(args) < 3 {
			//	log.G(cmd.Context()).Fatal("must enter runtime name")
			//}
			//if name == "" || namespace == "" || runtime == "" {
			//	//	log.G(cmd.Context()).Fatal("must enter runtime name")
			//}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			//return RunPipelineGet(ctx, args[0], args[1], args[2])
			return RunPipelineGet(ctx, name, namespace, runtime)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of target pipeline")
	util.Die(cmd.MarkFlagRequired("name"))
	cmd.Flags().StringVarP(&namespace, "namespace", "s", "", "Namespace of target pipeline")
	util.Die(cmd.MarkFlagRequired("namespace"))
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Runtime name of target pipeline")
	util.Die(cmd.MarkFlagRequired("runtime"))

	return cmd
}

func NewPipelineListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		//Use:   "list [runtime_name]",
		Short: "List all the pipelines under a specific runtime",
		Example: util.Doc(`
			<BIN> pipelines list runtime_name
		`),
		//PreRun: func(cmd *cobra.Command, args []string) {
		//	if len(args) < 1 {
		//		log.G(cmd.Context()).Fatal("must enter runtime name")
		//	}
		//},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunPipelineList(ctx)
		},
	}

	return cmd
}

func RunPipelineGet(ctx context.Context, name, namespace, runtime string) error {
	pipeline, err := cfConfig.NewClient().V2().Pipeline().Get(ctx, name, namespace, runtime)
	if err != nil {
		return err
	}

	if pipeline == nil {
		fields := log.Fields{
			"name": name,
			"namespace": namespace,
			"runtime": runtime,
		}
		log.G(ctx).WithFields(fields).Warn("pipeline was not found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tHEALTH STATUS\tSYNC STATUS")
	if err != nil {
		return err
	}

	healthStatus := "N/A"
	if pipeline.Self.HealthStatus != nil {
		healthStatus = pipeline.Self.HealthStatus.String()
	}
	_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
		pipeline.Metadata.Name,
		*pipeline.Metadata.Namespace,
		pipeline.Metadata.Runtime,
		healthStatus,
		pipeline.Self.SyncStatus.String(),
	)
	if err != nil {
		return err
	}

	return tb.Flush()
}

func RunPipelineList(ctx context.Context) error {
	pipelines, err := cfConfig.NewClient().V2().Pipeline().List(ctx, model.PipelinesFilterArgs{})
	if err != nil {
		return err
	}

	if len(pipelines) == 0 {
		log.G(ctx).Warn("no pipelines were found")
		//log.G(ctx).WithField("runtime", runtime).Warn("no pipelines were found in runtime")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tHEALTH STATUS\tSYNC STATUS")
	if err != nil {
		return err
	}

	for _, p := range pipelines {
		name := p.Metadata.Name
		namespace := *p.Metadata.Namespace
		runtime := p.Metadata.Runtime
		//createdAt := *p.Metadata.Created
		//syncStatus := "N/A"
		//if p.Self.SyncStatus.String() != "" {
		//	syncStatus = p.Self.SyncStatus.String()
		//}
		syncStatus := p.Self.SyncStatus.String()
		healthStatus := "N/A"
		if p.Self.HealthStatus != nil {
			healthStatus = p.Self.HealthStatus.String()
		}
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			runtime,
			healthStatus,
			syncStatus,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
