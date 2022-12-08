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
	"fmt"
	"github.com/spf13/cobra"
)

func NewSettingCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Settings commands",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}
	cmd.AddCommand(NewResetIscRepoUrlCommand())

	return cmd
}

func NewResetIscRepoUrlCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "reset-shared-config-repo",
		Short:             "Reset the URL of the shared configuration repo",
		Args:              cobra.NoArgs,
		PersistentPreRunE: cfConfig.RequireAuthentication,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var runtimesExist bool

			ctx := cmd.Context()

			runtimesExist, err = isRuntimesExist(ctx)
			if err != nil {
				return err
			}
			if runtimesExist {
				return fmt.Errorf("unable to reset the shared configuration repo as there are runtimes installed in the account. Uninstall all the runtimes from your account and try again")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			err := resetIscRepoUrl(ctx)
			if err != nil {
				return fmt.Errorf("failed to reset account Internal Shared Repository url: %w", err)
			}
			fmt.Printf("shared configuration repo was reset successfully \n")
			return nil
		},
	}

	return cmd
}
