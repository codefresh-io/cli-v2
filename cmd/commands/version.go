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
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"

	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	var opts struct {
		long bool
	}

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show cli version",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := store.Get()

			if opts.long {
				fmt.Printf("CLI:\n")
				fmt.Printf("    Version: %s\n", s.Version.Version)
				fmt.Printf("    BuildDate: %s\n", s.Version.BuildDate)
				fmt.Printf("    GitCommit: %s\n", s.Version.GitCommit)
				fmt.Printf("    GoVersion: %s\n", s.Version.GoVersion)
				fmt.Printf("    GoCompiler: %s\n", s.Version.GoCompiler)
				fmt.Printf("    Platform: %s\n", s.Version.Platform)

				// try to get app proxy version info
				if err := cfConfig.Load(cmd, args); err != nil {
					return err
				}

				runtime := ""
				var apClient codefresh.AppProxyAPI

				if err := getAppProxyClient(&runtime, &apClient)(cmd, args); err != nil {
					// can't create client, print error only if in debug level
					log.G(cmd.Context()).Debug(fmt.Errorf("failed to build app proxy client: %w", err))
					return nil
				}

				apInfo, err := apClient.VersionInfo().VersionInfo(cmd.Context())
				if err != nil {
					// can't get version, print error only if in debug level
					log.G(cmd.Context()).Debug(fmt.Errorf("failed to get app proxy version info: %w", err))
					return nil
				}

				fmt.Printf("\nAppProxy:\n")
				fmt.Printf("    Version: %s\n", apInfo.Version)
				fmt.Printf("    PlatformHost: %s\n", apInfo.PlatformHost)
				fmt.Printf("    PlatformVersion: %s\n", apInfo.PlatformVersion)
			} else {
				fmt.Printf("%+s\n", s.Version.Version)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.long, "long", false, "display full version information")

	return cmd
}
