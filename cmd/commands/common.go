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
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/config"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/manifoldco/promptui"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	die  = util.Die
	exit = os.Exit

	//go:embed assets/workflows-ingress-patch.json
	workflowsIngressPatch []byte

	cfConfig *config.Config

	GREEN           = "\033[32m"
	RED             = "\033[31m"
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

func IsValidIngressHost(ingress string) (bool, error) {
	return regexp.MatchString(`^(http|https)://`, ingress)
}

func askUserIfToInstallDemoResources(cmd *cobra.Command, sampleInstall *bool) error {
	if !store.Get().Silent && !cmd.Flags().Changed("sample-install") {
		templates := &promptui.SelectTemplates{
			Selected: "{{ . | yellow }} ",
		}

		labelStr := fmt.Sprintf("%vInstall Codefresh demo resources?%v", CYAN, COLOR_RESET)

		prompt := promptui.Select{
			Label:     labelStr,
			Items:     []string{"Yes (default)", "No"},
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
				die(cmd.Flags().Set("repo", *runtimeData.Repo))
				return nil
			}
		}
		if !store.Get().Silent {
			return getRepoFromUserInput(cmd)
		}
	}
	return nil
}

func getRepoFromUserInput(cmd *cobra.Command) error {
	repoPrompt := promptui.Prompt{
		Label: "Repository URL",
	}
	repoInput, err := repoPrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}
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
		Label:   "Runtime name",
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
			Selected: "{{ . | yellow }} ",
		}

		labelStr := fmt.Sprintf("%vSelect runtime%v", CYAN, COLOR_RESET)

		prompt := promptui.Select{
			Label:     labelStr,
			Items:     runtimeNames,
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
		return getGitTokenFromUserInput(cmd)
	}
	return nil
}

func getGitTokenFromUserInput(cmd *cobra.Command) error {
	gitTokenPrompt := promptui.Prompt{
		Label: "Git provider api token",
		Mask:  '*',
	}
	gitTokenInput, err := gitTokenPrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}
	die(cmd.Flags().Set("git-token", gitTokenInput))
	return nil
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
		promptStr += fmt.Sprintf("\n%v%v: %v%v", GREEN, key, COLOR_RESET, value)
	}
	log.G(ctx).Printf(promptStr)
	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"Yes", "No"},
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

func getKubeContextNameFromUserSelect(cmd *cobra.Command, kubeContextName *string) error {
	if store.Get().Silent {
		*kubeContextName, _ = cmd.Flags().GetString("context")
		return nil
	}

	configAccess := clientcmd.NewDefaultPathOptions()
	conf, err := configAccess.GetStartingConfig()
	if err != nil {
		return err
	}

	contextsList := conf.Contexts
	currentContext := conf.CurrentContext
	contextsNamesToShowUser := []string{currentContext + " (current)"}
	contextsIndex := []string{currentContext}

	for key := range contextsList {
		if key == currentContext {
			continue
		}
		contextsIndex = append(contextsIndex, key)
		contextsNamesToShowUser = append(contextsNamesToShowUser, key)
	}

	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	labelStr := fmt.Sprintf("%vSelect kube context%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     contextsNamesToShowUser,
		Templates: templates,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}

	result := contextsIndex[index]

	die(cmd.Flags().Set("context", result))
	*kubeContextName = result

	return nil
}

func getIngressHostFromUserInput(cmd *cobra.Command, ingressHost *string) error {
	if ingressHost != nil && *ingressHost != "" {
		*ingressHost = strings.TrimSpace(*ingressHost)
		return nil
	}

	if store.Get().Silent {
		return fmt.Errorf("missing ingress host")
	}

	ingressHostPrompt := promptui.Prompt{
		Label: "Ingress host (required)",
	}

	ingressHostInput, err := ingressHostPrompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}

	ingressHostInput = strings.TrimSpace(ingressHostInput)
	if ingressHostInput == "" {
		return fmt.Errorf("missing ingress host")
	}

	die(cmd.Flags().Set("ingress-host", ingressHostInput))
	*ingressHost = ingressHostInput

	return nil
}

func ingressHostCertificateCheck(ctx context.Context, ingress string) (bool, error) {
	httpsIngress := ingress
	var err error
	match, _ := regexp.MatchString(`^http://`, httpsIngress)
	if match {
		httpsIngress, err = httpToHttps(ingress)
		if err != nil {
			return false, err
		}
	}

	res, err := http.Get(httpsIngress)

	if err != nil {
		urlErr, ok := err.(*url.Error)
		if !ok {
			return false, err
		}
		_, ok1 := urlErr.Err.(x509.CertificateInvalidError)
		_, ok2 := urlErr.Err.(x509.SystemRootsError)
		_, ok3 := urlErr.Err.(x509.UnknownAuthorityError)
		_, ok4 := urlErr.Err.(x509.ConstraintViolationError)
		_, ok5 := urlErr.Err.(x509.HostnameError)

		if ok1 || ok2 || ok3 || ok4 || ok5 {
			insecureOk := checkIngressHostWithInsecure(httpsIngress)
			if insecureOk {
				if match { //if user provided http ingress
					log.G(ctx).Warn("")
				}
				return true, nil
			}
		}
		return false, err
	}
	res.Body.Close()

	return false, nil
}

func checkIngressHostWithInsecure(ingress string) bool {
	httpClient := &http.Client{}
	httpClient.Timeout = 10 * time.Second
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpClient.Transport = customTransport
	req, err := http.NewRequest("GET", ingress, nil)
	if err != nil {
		return false
	}
	_, err = httpClient.Do(req)
	
	return err == nil
}

func httpToHttps(rawUrl string) (string, error) {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	parsedUrl.Scheme = "https"
	return parsedUrl.String(), nil
}

func askUserIfToProceedWithInsecure(cmd *cobra.Command) error {
	if store.Get().Silent || store.Get().InsecureIngressHost {
		return nil
	}
	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	labelStr := fmt.Sprintf("%vThe provided ingressHost does not have a certificate. Do you wish to continue with insecure ingress host mode?%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"No (default)", "Yes", "Cancel installation"},
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}

	if result == "Yes" {
		store.Get().InsecureIngressHost = true
	} else if result == "Cancel installation" {
		log.G(cmd.Context()).Fatal("installation was cancelled")
	}
	return nil
}
