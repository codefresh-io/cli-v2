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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func getControllerName(s string) string {
	split := strings.Split(s, "/")
	return split[1]
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
	if cloneOpts.Repo != "" {
		return nil
	}

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
		err := getRepoFromUserInput(cmd)
		if err != nil {
			return err
		}
	}

	if cloneOpts.Repo == "" {
		return fmt.Errorf("must enter a valid installation repository URL")
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

func getIngressClassFromUserSelect(ctx context.Context, ingressClassNames []string, ingressClass *string) error {
	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	labelStr := fmt.Sprintf("%vSelect ingressClass%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     ingressClassNames,
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}

	*ingressClass = result

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

func getIngressHostFromCluster(ctx context.Context, opts *RuntimeInstallOptions) error {
	log.G(ctx).Info("Retrieving ingress controller info from your cluster...\n")

	cs := opts.KubeFactory.KubernetesClientSetOrDie()
	ServicesList, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ingress controller info from your cluster: %w", err)
	}

	for _, s := range ServicesList.Items {
		if s.ObjectMeta.Name == opts.IngressController {
			ingress := s.Status.LoadBalancer.Ingress[0]
			if ingress.Hostname != "" {
				opts.IngressHost = fmt.Sprintf("https://%s", ingress.Hostname)
			} else {
				opts.IngressHost = fmt.Sprintf("https://%s", ingress.IP)
			}
			break
		}
	}

	if opts.IngressController == "" {
		return fmt.Errorf("failed to fetch ingress host from the cluster. please make sure you have a nginx ingress controller installed properly")
	}

	return nil
}

func checkIngressHostCertificate(ctx context.Context, ingress string) (bool, error) {
	var err error

	res, err := http.Get(ingress)

	if err == nil {
		res.Body.Close()
		return true, nil
	}

	urlErr, ok := err.(*url.Error)
	if !ok {
		return false, err
	}
	_, ok1 := urlErr.Err.(x509.CertificateInvalidError)
	_, ok2 := urlErr.Err.(x509.SystemRootsError)
	_, ok3 := urlErr.Err.(x509.UnknownAuthorityError)
	_, ok4 := urlErr.Err.(x509.ConstraintViolationError)
	_, ok5 := urlErr.Err.(x509.HostnameError)

	certErr := ok1 || ok2 || ok3 || ok4 || ok5
	if !certErr {
		return false, fmt.Errorf("failed with non-certificate error: %w", err)
	}

	insecureOk := checkIngressHostWithInsecure(ingress)
	if !insecureOk {
		return false, fmt.Errorf("insecure call failed: %w", err)
	}

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
	res, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	res.Body.Close()
	return true
}

func askUserIfToProceedWithInsecure(ctx context.Context) error {
	if store.Get().InsecureIngressHost {
		return nil
	}
	if store.Get().Silent {
		return fmt.Errorf("cancelled installation due to invalid ingress host certificate")
	}

	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	log.G(ctx).Warnf("The ingress host does not have a valid certificate.")
	labelStr := fmt.Sprintf("%vDo you wish to continue the installation with insecure ingress host mode?%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"Yes", "Cancel installation"},
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("Prompt error: %w", err)
	}

	if result == "Yes" {
		store.Get().InsecureIngressHost = true
	} else {
		return fmt.Errorf("cancelled installation due to invalid ingress host certificate")
	}
	return nil
}
