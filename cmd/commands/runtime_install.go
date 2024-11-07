// Copyright 2024 The Codefresh Authors.
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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func NewRuntimeInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "install [runtime_name]",
		Deprecated: "We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return errors.New(`We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.
As of January 30, 2024, CLI-based Runtimes are no longer supported.
If you're currently using CLI-based Hybrid GitOps Runtimes, we encourage you to migrate to Helm by following our migration guidelines (https://codefresh.io/docs/docs/installation/gitops/migrate-cli-runtimes-helm).
For Helm installation, review our documentation on installing Hybrid GitOps Runtimes (https://codefresh.io/docs/docs/installation/gitops/hybrid-gitops-helm-installation).`)
		},
	}

	return cmd
}

func checkExistingRuntimes(ctx context.Context, runtime string) error {
	_, err := getRuntime(ctx, runtime)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil // runtime does not exist
		}

		return fmt.Errorf("failed to get runtime: %w", err)
	}

	return fmt.Errorf("runtime \"%s\" already exists", runtime)
}
