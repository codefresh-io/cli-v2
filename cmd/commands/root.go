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
	"github.com/codefresh-io/cli-v2/pkg/config"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/spf13/cobra"
)

func NewRoot() *cobra.Command {
	s := store.Get()

	cmd := &cobra.Command{
		Use:   s.BinaryName,
		Short: util.Doc(`<BIN> is used for installing and managing codefresh installations using gitops`),
		Long: util.Doc(`<BIN> is used for installing and managing codefresh installations using gitops.
		
Most of the commands in this CLI require you to specify a personal access token
for your git provider. This token is used to authenticate with your git provider
when performing operations on the gitops repository, such as cloning it and
pushing changes to it.

It is recommended that you export the $GIT_TOKEN and $GIT_REPO environment
variables in advanced to simplify the use of those commands.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		SilenceUsage:      true, // will not display usage when RunE returns an error
		SilenceErrors:     true, // will not use fmt to print errors
		DisableAutoGenTag: true, // disable the date in the command docs
	}

	cfConfig = config.AddFlags(cmd.PersistentFlags())

	cmd.AddCommand(NewVersionCommand())
	cmd.AddCommand(NewConfigCommand())
	cmd.AddCommand(NewRuntimeCommand())
	cmd.AddCommand(NewGitSourceCommand())
	cmd.AddCommand(NewComponentCommand())
	cmd.AddCommand(NewWorkflowCommand())
	cmd.AddCommand(NewPipelineCommand())
	cmd.AddCommand(NewIntegrationCommand())

	cobra.OnInitialize(func() { postInitCommands(cmd.Commands()) })

	return cmd
}
