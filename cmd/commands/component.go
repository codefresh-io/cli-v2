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
	"io"
	"os"

	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/util"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
)

type ()

func newComponentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "component",
		Short:             "Manage components of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(newComponentListCommand())

	return cmd
}

func newComponentListCommand() *cobra.Command {
	var runtimeName string

	cmd := &cobra.Command{
		Use:   "list RUNTIME_NAME",
		Short: "List all the components under a specific runtime",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
			<BIN> component list runtime_name
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			runtimeName, err = ensureRuntimeName(cmd.Context(), args, nil)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runComponentList(cmd.Context(), runtimeName)
		},
	}

	return cmd
}

func runComponentList(ctx context.Context, runtimeName string) error {
	components, err := cfConfig.NewClient().GraphQL().Component().List(ctx, runtimeName)
	if err != nil {
		return err
	}

	if len(components) == 0 {
		log.G(ctx).WithField("runtime", runtimeName).Warn("no components were found in runtime")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)

	if err := printComponents(tb, components); err != nil {
		return err
	}

	return tb.Flush()
}

func printComponents(w io.Writer, components []platmodel.Component) error {
	_, err := fmt.Fprintln(w, "NAME\tHEALTH STATUS\tSYNC STATUS\tVERSION")
	if err != nil {
		return err
	}

	for _, c := range components {
		if err := printComponent(w, c); err != nil {
			return err
		}
	}

	return nil
}

func printComponent(w io.Writer, c platmodel.Component) error {
	name := c.Metadata.Name
	healthStatus := "N/A"
	syncStatus := "N/A"
	version := c.Version

	if c.Self != nil {
		if c.Self.Status != nil {
			syncStatus = c.Self.Status.SyncStatus.String()
		}

		if c.Self.Status.HealthStatus != nil {
			healthStatus = c.Self.Status.HealthStatus.String()
		}
	}

	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
		name,
		healthStatus,
		syncStatus,
		version,
	)

	return err
}
