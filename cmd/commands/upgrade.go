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

package commands

import (
	"github.com/spf13/cobra"

	cliutil "github.com/codefresh-io/cli-v2/pkg/util/cli"
)

func NewUpgradeCommand() *cobra.Command {
	var opts struct {
		version string
	}

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrades the cli",
		Annotations: map[string]string{
			cliutil.SkipVersionCheck: "true",
		},
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cliutil.UpgradeCLIToVersion(cmd.Context(), opts.version)
		},
	}

	cmd.Flags().StringVar(&opts.version, "version", "", "specify a cli version to upgrade to")

	return cmd
}
