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
	_ "embed"
	"fmt"
	"os"
	"regexp"

	"github.com/Masterminds/semver/v3"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/config"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/manifoldco/promptui"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	die  = util.Die
	exit = os.Exit

	//go:embed assets/ingress-patch.json
	ingressPatch []byte

	cfConfig *config.Config
)

func postInitCommands(commands []*cobra.Command) {
	for _, cmd := range commands {
		presetRequiredFlags(cmd)
		if cmd.HasSubCommands() {
			postInitCommands(cmd.Commands())
		}
	}
}

func presetRequiredFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && f.Value.String() == "" {
			die(cmd.Flags().Set(f.Name, viper.GetString(f.Name)))
		}
	})
	cmd.Flags().SortFlags = false
}

func IsValid(s string) (bool, error) {
	return regexp.MatchString(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`, s)
}

func ensureRepo(cmd *cobra.Command, runtimeName string, cloneOpts *git.CloneOptions) error {
	ctx := cmd.Context()
	if cloneOpts.Repo == "" {
		runtimeData, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
		if err != nil {
			return fmt.Errorf("failed getting runtime repo information: %w", err)
		}
		if runtimeData.Repo != nil {
			cloneOpts.Repo = *runtimeData.Repo
			die(cmd.Flags().Set("repo", *runtimeData.Repo))
		} else {
			return getRepoFromUserInput(cmd, cloneOpts)
		}
	}
	return nil
}

func getRepoFromUserInput(cmd *cobra.Command, cloneOpts *git.CloneOptions) error {
	repoPrompt := promptui.Prompt{
		Label: "Insert repo",
	}
	repoInput, err := repoPrompt.Run()
	if err != nil {
		return fmt.Errorf("Input error: %w", err)
	}
	cloneOpts.Repo = repoInput
	die(cmd.Flags().Set("repo", repoInput))
	return nil
}

func getRuntimeNameFromUserInput(runtimeName *string) error {
	runtimeNamePrompt := promptui.Prompt{
		Label: "Insert runtime name",
	}
	runtimeNameInput, err := runtimeNamePrompt.Run()
	if err != nil {
		return fmt.Errorf("Input error: %w", err)
	}
	*runtimeName = runtimeNameInput
	return nil
}

func verifyLatestVersion(ctx context.Context) error {
	latestVersionString, err := cfConfig.NewClient().V2().CliReleases().GetLatest(ctx)
	if err != nil {
		return fmt.Errorf("failed getting latest cli release: %w", err)
	}
	
	latestVersionSemver := semver.MustParse(latestVersionString)
	currentVersion := store.Get().Version.Version

	if currentVersion.LessThan(latestVersionSemver) {
		return fmt.Errorf("please upgrade to the latest cli version: %s", latestVersionString)
	}

	return nil
}
