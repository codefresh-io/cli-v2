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

func newPipelineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "pipeline",
		Short:             "Manage pipelines of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(newPipelineGetCommand())
	cmd.AddCommand(newPipelineListCommand())

	return cmd
}

func newPipelineGetCommand() *cobra.Command {
	var (
		name      string
		namespace string
		runtime   string
	)

	cmd := &cobra.Command{
		Use:   "get --runtime <runtime> --namespace <namespace> --name <name>",
		Short: "Get a pipeline under a specific runtime and namespace",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
			<BIN> pipeline --runtime runtime_name --namespace namespace --name pipeline_name

			<BIN> pipeline -r runtime_name -N namespace -n pipeline_name
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			return runPipelineGet(ctx, name, namespace, runtime)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of target pipeline")
	util.Die(cmd.MarkFlagRequired("name"))
	cmd.Flags().StringVarP(&namespace, "namespace", "N", "", "Namespace of target pipeline")
	util.Die(cmd.MarkFlagRequired("namespace"))
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Runtime name of target pipeline")
	util.Die(cmd.MarkFlagRequired("runtime"))

	return cmd
}

func newPipelineListCommand() *cobra.Command {
	var (
		name      string
		namespace string
		runtime   string
		project   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all the pipelines",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
			<BIN> pipelines list

			<BIN> pipelines list --runtime <runtime>

			<BIN> pipelines list -r <runtime>
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			filterArgs := platmodel.PipelinesFilterArgs{
				Name:      &name,
				Namespace: &namespace,
				Runtime:   &runtime,
				Project:   &project,
			}
			return runPipelineList(ctx, filterArgs)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Filter by pipeline name")
	cmd.Flags().StringVarP(&namespace, "namespace", "N", "", "Filter by pipeline namespace")
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Filter by pipeline runtime")
	cmd.Flags().StringVarP(&project, "project", "p", "", "Filter by pipeline project")

	return cmd
}

func runPipelineGet(ctx context.Context, name, namespace, runtime string) error {
	pipeline, err := cfConfig.NewClient().GraphQL().Pipeline().Get(ctx, name, namespace, runtime)
	if err != nil {
		return err
	}

	if pipeline == nil {
		fields := log.Fields{
			"name":      name,
			"namespace": namespace,
			"runtime":   runtime,
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
		pipeline.Self.SyncStatus,
	)
	if err != nil {
		return err
	}

	return tb.Flush()
}

func runPipelineList(ctx context.Context, filterArgs platmodel.PipelinesFilterArgs) error {
	pipelines, err := cfConfig.NewClient().GraphQL().Pipeline().List(ctx, filterArgs)
	if err != nil {
		return err
	}

	if len(pipelines) == 0 {
		log.G(ctx).Warn("no pipelines were found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tRUNTIME\tHEALTH STATUS\tSYNC STATUS")
	if err != nil {
		return err
	}

	for _, p := range pipelines {
		healthStatus := "N/A"
		if p.Self.HealthStatus != nil {
			healthStatus = p.Self.HealthStatus.String()
		}
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			p.Metadata.Name,
			*p.Metadata.Namespace,
			p.Metadata.Runtime,
			healthStatus,
			p.Self.SyncStatus,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
