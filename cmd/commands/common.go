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
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/codefresh-io/cli-v2/internal/config"
	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/store"
	"github.com/codefresh-io/cli-v2/internal/util"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	die  = util.Die
	exit = os.Exit

	cfConfig config.Config

	RED             = "\033[31m"
	GREEN           = "\033[32m"
	YELLOW          = "\033[33m"
	CYAN            = "\033[36m"
	BOLD            = "\033[1m"
	UNDERLINE       = "\033[4m"
	COLOR_RESET     = "\033[0m"
	UNDERLINE_RESET = "\033[24m"
	BOLD_RESET      = "\033[22m"
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

func IsValidName(s string) (bool, error) {
	return regexp.MatchString(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`, s)
}

func ensureRuntimeName(ctx context.Context, args []string, filter func(runtime *platmodel.Runtime) bool) (string, error) {
	var (
		runtimeName string
		err         error
	)

	if len(args) > 0 && args[0] != "" {
		runtimeName := args[0]
		isRuntimeExists := checkExistingRuntimes(ctx, runtimeName)
		if isRuntimeExists == nil {
			return "", fmt.Errorf("there is no runtime by the name: %s", runtimeName)
		}

		return runtimeName, nil
	}

	if !store.Get().Silent {
		runtimeName, err = getRuntimeNameFromUserSelect(ctx, filter)
		if err != nil {
			return "", err
		}
	}

	if runtimeName == "" {
		return "", fmt.Errorf("must supply value for \"Runtime name\"")
	}

	return runtimeName, nil
}

func getRuntimeNameFromUserSelect(ctx context.Context, filter func(runtime *platmodel.Runtime) bool) (string, error) {
	runtimes, err := cfConfig.NewClient().GraphQL().Runtime().List(ctx)
	if err != nil {
		return "", err
	}

	var filteredRuntimes []platmodel.Runtime
	if filter != nil {
		filteredRuntimes = make([]platmodel.Runtime, 0)
		for _, rt := range runtimes {
			if filter(&rt) {
				filteredRuntimes = append(filteredRuntimes, rt)
			}
		}
	} else {
		filteredRuntimes = runtimes
	}

	if len(filteredRuntimes) == 0 {
		return "", fmt.Errorf("no runtimes were found")
	}

	if len(filteredRuntimes) == 1 {
		log.G(ctx).Printf("%vUsing runtime '%s'%v\n", YELLOW, filteredRuntimes[0].Metadata.Name, COLOR_RESET)
		return filteredRuntimes[0].Metadata.Name, nil
	}

	templates := &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%s {{ .Metadata.Name | underline }}{{ if  ne .InstallationType \"HELM\" }}{{ printf \" (%%s)\" .InstallationType | underline }}{{ end }}", promptui.IconSelect),
		Inactive: "  {{ .Metadata.Name }}{{ if  ne .InstallationType \"HELM\" }}{{ printf \" (%s)\" .InstallationType }}{{ end }}",
		Selected: "{{ .Metadata.Name | yellow }}",
	}

	labelStr := fmt.Sprintf("%vSelect runtime%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     filteredRuntimes,
		Templates: templates,
	}

	i, _, err := prompt.Run()
	return filteredRuntimes[i].Metadata.Name, err
}

func getApprovalFromUser(ctx context.Context, finalParameters map[string]string, description string) error {
	if store.Get().Silent {
		return nil
	}

	isApproved, err := promptSummaryToUser(ctx, finalParameters, description)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if !isApproved {
		return fmt.Errorf("%v command was cancelled by user", description)
	}

	return nil
}

func promptSummaryToUser(ctx context.Context, finalParameters map[string]string, description string) (bool, error) {
	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}
	promptStr := fmt.Sprintf("%v%v%vSummary%v%v%v", GREEN, BOLD, UNDERLINE, COLOR_RESET, BOLD_RESET, UNDERLINE_RESET)
	labelStr := fmt.Sprintf("%vDo you wish to continue with %v?%v", CYAN, description, COLOR_RESET)

	for key, value := range finalParameters {
		if value != "" {
			promptStr += fmt.Sprintf("\n%v%v: %v%v", GREEN, key, COLOR_RESET, value)
		}
	}
	log.G(ctx).Printf(promptStr)
	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"Yes", "No"},
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return false, err
	}

	if result == "Yes" {
		return true, nil
	}
	return false, nil
}

func ensureKubeContextName(context, kubeconfig *pflag.Flag) (string, error) {
	contextName, err := getKubeContextName(context, kubeconfig)
	if err != nil {
		return "", err
	}

	if contextName == "" {
		return "", fmt.Errorf("must supply value for \"%s\"", context.Name)
	}

	return contextName, nil
}

func getKubeContextName(context, kubeconfig *pflag.Flag) (string, error) {
	kubeconfigPath := kubeconfig.Value.String()

	contextName := context.Value.String()
	if contextName != "" {
		if !util.CheckExistingContext(contextName, kubeconfigPath) {
			return "", fmt.Errorf("kubeconfig file missing context \"%s\"", contextName)
		}

		return contextName, nil
	}

	if !store.Get().Silent {
		var err error
		contextName, err = getKubeContextNameFromUserSelect(kubeconfigPath)
		if err != nil {
			return "", err
		}
	}

	if contextName == "" {
		contextName = util.KubeCurrentContextName(kubeconfigPath)
		log.G().Infof("Using current kube context '%s'", contextName)
	}

	return contextName, context.Value.Set(contextName)
}

func getKubeContextNameFromUserSelect(kubeconfig string) (string, error) {
	contexts := util.KubeContexts(kubeconfig)
	templates := &promptui.SelectTemplates{
		Active:   "▸ {{ .Name }} {{if .Current }}(current){{end}}",
		Inactive: "  {{ .Name }} {{if .Current }}(current){{end}}",
		Selected: "{{ .Name | yellow }}",
	}

	labelStr := fmt.Sprintf("%vSelect kube context%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     contexts,
		Templates: templates,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return contexts[index].Name, nil
}

func getIscRepo(ctx context.Context) (string, error) {
	currentUser, err := cfConfig.NewClient().GraphQL().User().GetCurrent(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get current user from platform: %w", err)
	}

	if currentUser.ActiveAccount.SharedConfigRepo == nil {
		return "", nil
	}

	return *currentUser.ActiveAccount.SharedConfigRepo, nil
}

func getRuntime(ctx context.Context, runtimeName string) (*platmodel.Runtime, error) {
	rt, err := cfConfig.NewClient().GraphQL().Runtime().Get(ctx, runtimeName)
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime from platform. error: %w", err)
	}

	return rt, nil
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
