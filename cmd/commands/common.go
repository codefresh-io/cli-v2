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
	"github.com/codefresh-io/cli-v2/pkg/log"
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

	GREEN = "\033[32m"
	CYAN = "\033[36m"
	BOLD = "\033[1m"
	UNDERLINE = "\033[4m"
	COLOR_RESET = "\033[0m"
	UNDERLINE_RESET = "\033[24m"
	BOLD_RESET = "\033[22m"
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

func askUserIfToInstallCodefreshSamples(cmd *cobra.Command, sampleInstall *bool) error {
	if !store.Get().Silent && !cmd.Flags().Changed("sample-install") {
		templates := &promptui.SelectTemplates{
			Selected:  "{{ . | yellow }} ",
		}

		labelStr := fmt.Sprintf("%vInstall codefresh samples?%v", CYAN, COLOR_RESET)

		prompt := promptui.Select{
			Label: labelStr,
			Items: []string {"Yes (default)", "No"},
			Templates: templates,
		}
		
		_, result, err := prompt.Run()
		if err != nil {
			return fmt.Errorf("Prompt error: %w", err)
		}

		if result == "No" {
			*sampleInstall = false
		}
	}
	return nil
}

func ensureRepo(cmd *cobra.Command, runtimeName string, cloneOpts *git.CloneOptions, fromAPI bool) error {
	ctx := cmd.Context()
	if cloneOpts.Repo == "" {
		if fromAPI {
			runtimeData, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
			if err != nil {
				return fmt.Errorf("failed getting runtime repo information: %w", err)
			}
			if runtimeData.Repo != nil {
				cloneOpts.Repo = *runtimeData.Repo
				die(cmd.Flags().Set("repo", *runtimeData.Repo))
				return nil
			} 
		} 
		if !store.Get().Silent {
			return getRepoFromUserInput(cmd, cloneOpts)
		}
	}
	return nil
}

func getRepoFromUserInput(cmd *cobra.Command, cloneOpts *git.CloneOptions) error {
	repoPrompt := promptui.Prompt{
		Label: "Repository URL",
	}
	repoInput, err := repoPrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}
	cloneOpts.Repo = repoInput
	die(cmd.Flags().Set("repo", repoInput))
	return nil
}

func ensureRuntimeName(ctx context.Context, args []string, runtimeName *string) error {
	if len(args) > 0 {
		*runtimeName = args[0]
	}

	if *runtimeName == "" {
		if !store.Get().Silent {
			return getRuntimeNameFromUserSelect(ctx, runtimeName)
		}
		log.G(ctx).Fatal("must enter a runtime name")
	}

	return nil
}

func getRuntimeNameFromUserInput(runtimeName *string) error {
	runtimeNamePrompt := promptui.Prompt{
		Label: "Runtime name",
		Default: "codefresh",
		Pointer: promptui.PipeCursor,
	}
	runtimeNameInput, err := runtimeNamePrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}
	*runtimeName = runtimeNameInput
	return nil
}

func getRuntimeNameFromUserSelect(ctx context.Context, runtimeName *string) error {
	if !store.Get().Silent {
		runtimes, err := cfConfig.NewClient().V2().Runtime().List(ctx)
		if err != nil {
			return err
		}

		if len(runtimes) == 0 {
			return fmt.Errorf("No runtimes were found")
		}

		runtimeNames := make([]string, len(runtimes))

		for index, rt := range runtimes {
			runtimeNames[index] = rt.Metadata.Name
		}

		templates := &promptui.SelectTemplates{
			Selected:  "{{ . | yellow }} ",
		}

		labelStr := fmt.Sprintf("%vSelect runtime%v", CYAN, COLOR_RESET)

		prompt := promptui.Select{
			Label: labelStr,
			Items: runtimeNames,
			Templates: templates,
		}
		
		_, result, err := prompt.Run()
		if err != nil {
			return fmt.Errorf("Prompt error: %w", err)
		}

		*runtimeName = result
	}
	return nil
}

func ensureGitToken(cmd *cobra.Command, cloneOpts *git.CloneOptions) error {
	if cloneOpts.Auth.Password == "" && !store.Get().Silent {
		return getGitTokenFromUserInput(cmd, cloneOpts)
	}
	return nil
}

func getGitTokenFromUserInput(cmd *cobra.Command, cloneOpts *git.CloneOptions) error {
	gitTokenPrompt := promptui.Prompt{
		Label: "Git provider api token",
	}
	gitTokenInput, err := gitTokenPrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}
	cloneOpts.Auth.Password = gitTokenInput
	die(cmd.Flags().Set("git-token", gitTokenInput))
	return nil
}

func getApprovalFromUser(ctx context.Context, finalParameters map[string]string, description string) (bool, error) {
	if !store.Get().Silent {
		isApproved, err := promptSummaryToUser(ctx, finalParameters, description)
		if err != nil {
			return false, fmt.Errorf("%w", err)
		}

		if !isApproved {
			log.G(ctx).Printf("%v command was cancelled by user", description)
			return false, nil
		}
	}
	return true, nil
}

func promptSummaryToUser(ctx context.Context, finalParameters map[string]string, description string) (bool, error) {
	templates := &promptui.SelectTemplates{
		Selected:  "{{ . | yellow }} ",
	}
	promptStr := fmt.Sprintf("%v%v%vSummary%v%v%v", GREEN, BOLD, UNDERLINE, COLOR_RESET, BOLD_RESET, UNDERLINE_RESET)
	labelStr := fmt.Sprintf("%vDo you wish to continue with %v?%v", CYAN, description, COLOR_RESET)

	for key, value := range finalParameters {
		promptStr += fmt.Sprintf("\n%v%v: %v%v", GREEN, key, COLOR_RESET, value)
	}
	log.G(ctx).Printf(promptStr)
	prompt := promptui.Select{
		Label: labelStr,
		Items: []string{"Yes", "No"},
		Templates: templates,
	}
	
	_, result, err := prompt.Run()
	if err != nil {
		return false, fmt.Errorf("Prompt error: %w", err)
	}

	if result == "Yes" {
		return true, nil
	}
	return false, nil
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
