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
	"encoding/json"
	"fmt"
	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/util"
	"github.com/spf13/cobra"
)

type (
	ValidateLimitsOptions struct {
		hook bool
	}
)

func NewAccountCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Account related commands",
		Args:  cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewValidateLimitsCommand())

	return cmd
}

func NewValidateLimitsCommand() *cobra.Command {
	opts := &ValidateLimitsOptions{}

	cmd := &cobra.Command{
		Use:               "validate-limits",
		Aliases:           []string{"vl"},
		Args:              cobra.NoArgs,
		Short:             "Validate account limits",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Example:           util.Doc("<BIN> account validate-limits"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runValidateLimits(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("failed validating limits: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.hook, "hook", false, "set to true when running inside a helm-hook")

	util.Die(cmd.Flags().MarkHidden("hook"))

	return cmd
}

func runValidateLimits(ctx context.Context, opts *ValidateLimitsOptions) error {
	log.G(ctx).Info("Validating account limits")
	if opts.hook {
		log.G(ctx).Info("Running in hook-mode")
	}

	limitsStatus, err := cfConfig.NewClient().GraphQL().Payments().GetLimitsStatus(ctx)
	statusString, _ := json.MarshalIndent(limitsStatus, "", "  ")

	if err != nil {
		return err
	}

	if !limitsStatus.Status {
		return fmt.Errorf("account limits exceeded for account: %s", string(statusString))
	}

	if opts.hook && limitsStatus.Limits.Clusters == limitsStatus.Usage.Clusters {
		limitsStatus.Status = false
		statusString, _ := json.MarshalIndent(limitsStatus, "", "  ")
		return fmt.Errorf("account limits (clusters) exceeded for account: %s", string(statusString))
	}

	log.G(ctx).Infof("Successfully validated limits for account")
	return nil
}
