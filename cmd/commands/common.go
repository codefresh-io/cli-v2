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

	"github.com/codefresh-io/cli-v2/pkg/config"
	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	errUserCanceledInsecureInstall = fmt.Errorf("cancelled installation due to invalid ingress host certificate")
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

func isValidIngressHost(ingressHost string) (bool, error) {
	return regexp.MatchString(`^(http|https)://`, ingressHost)
}

func askUserIfToInstallDemoResources(cmd *cobra.Command, sampleInstall *bool) error {
	if !store.Get().Silent && !cmd.Flags().Changed("demo-resources") {
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
			return err
		}

		if result == "No" {
			*sampleInstall = false
		}
	}

	return nil
}

func ensureRepo(cmd *cobra.Command, runtimeName string, cloneOpts *apgit.CloneOptions, fromAPI bool) error {
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
		return fmt.Errorf("must enter a valid installation repository URL, using --repo")
	}

	return nil
}

func getRepoFromUserInput(cmd *cobra.Command) error {
	repoPrompt := promptui.Prompt{
		Label: "Repository URL",
		Validate: func(value string) error {
			host, orgRepo, _, _, _, _, _ := aputil.ParseGitUrl(value)
			if host != "" && orgRepo != "" {
				return nil
			}
			return fmt.Errorf("Invalid URL for Git repository")
		},
	}
	repoInput, err := repoPrompt.Run()
	if err != nil {
		return err
	}

	return cmd.Flags().Set("repo", repoInput)
}

func ensureRuntimeName(ctx context.Context, args []string, allowManaged bool) (string, error) {
	var (
		runtimeName string
		err         error
	)

	if len(args) > 0 {
		return args[0], nil
	}

	if !store.Get().Silent {
		runtimeName, err = getRuntimeNameFromUserSelect(ctx, allowManaged)
		if err != nil {
			return "", err
		}
	}

	if runtimeName == "" {
		return "", fmt.Errorf("must supply value for \"Runtime name\"")
	}

	return runtimeName, nil
}

func getRuntimeNameFromUserSelect(ctx context.Context, allowManaged bool) (string, error) {
	runtimes, err := cfConfig.NewClient().V2().Runtime().List(ctx)
	if err != nil {
		return "", err
	}

	if len(runtimes) == 0 {
		return "", fmt.Errorf("no runtimes were found")
	}

	var runtimeNames []string

	for _, rt := range runtimes {
		rtDisplay := rt.Metadata.Name
		if rt.Managed {
			if !allowManaged {
				// preventing hosted runtimes to prompt
				continue
			}
			rtDisplay = fmt.Sprintf("%s (hosted)", rtDisplay)
		}
		runtimeNames = append(runtimeNames, rtDisplay)
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
	resultSplit := strings.Split(result, " ")
	return resultSplit[0], err
}

func getRuntimeNameFromUserInput() (string, error) {
	runtimeName, err := getValueFromUserInput("Runtime name", "codefresh", validateRuntimeName)
	return runtimeName, err
}

func validateRuntimeName(runtime string) error {
	isValid, err := IsValidName(runtime)
	if err != nil {
		return fmt.Errorf("failed to validate runtime name: %w", err)
	}
	if !isValid {
		return fmt.Errorf("Runtime name must start with a lower-case character, and can include up to 62 lower-case characters and numbers")
	}
	return nil
}

func getValueFromUserInput(label, defaultValue string, validate promptui.ValidateFunc) (string, error) {
	prompt := promptui.Prompt{
		Label:    label,
		Default:  defaultValue,
		Validate: validate,
		Pointer:  promptui.PipeCursor,
	}

	return prompt.Run()
}

// ensureGitRuntimeToken gets the runtime token from the user (if !silent), and verifys it with he provider (if available)
func ensureGitRuntimeToken(cmd *cobra.Command, gitProvider cfgit.Provider, cloneOpts *apgit.CloneOptions) error {
	ctx := cmd.Context()
	errMessage := "Value stored in environment variable GIT_TOKEN is invalid; enter a valid runtime token: %w"
	if cloneOpts.Auth.Password == "" && !store.Get().Silent {
		err := getGitTokenFromUserInput(cmd)
		errMessage = "Invalid runtime token; enter a valid token: %w"
		if err != nil {
			return err
		}
	}

	if gitProvider != nil {
		err := gitProvider.VerifyRuntimeToken(ctx, cloneOpts.Auth)
		if err != nil {
			// in case when we get invalid value from env variable TOKEN we clean
			cloneOpts.Auth.Password = ""
			return fmt.Errorf(errMessage, err)
		}
		if cloneOpts.Auth.Username == "" && gitProvider.Type() == cfgit.BITBUCKET {
			return fmt.Errorf("must provide a git user using --git-user for bitbucket cloud")
		}
	} else if cloneOpts.Auth.Password == "" {
		return fmt.Errorf("must provide a git token using --git-token")
	}

	return nil
}

// ensureGitUserToken verifys the user's Personal Access Token (if it is different from the Runtime Token)
func ensureGitUserToken(ctx context.Context, opts *RuntimeInstallOptions) error {
	if opts.GitIntegrationRegistrationOpts.Token == "" {
		opts.GitIntegrationRegistrationOpts.Token = opts.InsCloneOpts.Auth.Password
		currentUser, err := cfConfig.GetCurrentContext().GetUser(ctx)
		if err != nil {
			return fmt.Errorf("failed to get current user from platform: %w", err)
		}

		log.G(ctx).Infof("Personal git token was not provided. Using runtime git token to register user: \"%s\". You may replace your personal git token at any time from the UI in the user settings", currentUser.Name)

		opts.GitIntegrationRegistrationOpts.Username = opts.InsCloneOpts.Auth.Username

		return nil
	}

	if opts.gitProvider != nil {
		auth := apgit.Auth{
			Password: opts.GitIntegrationRegistrationOpts.Token,
			Username: opts.GitIntegrationRegistrationOpts.Username,
		}
		return opts.gitProvider.VerifyUserToken(ctx, auth)
	}

	return nil
}

func getGitTokenFromUserInput(cmd *cobra.Command) error {
	gitTokenPrompt := promptui.Prompt{
		Label: "Runtime git api token",
		Mask:  '*',
	}
	gitTokenInput, err := gitTokenPrompt.Run()
	if err != nil {
		return err
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

type SelectItem struct {
	Value string
	Label string
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

func validateIngressHost(ingressHost string) error {
	isValid, err := isValidIngressHost(ingressHost)
	if err != nil {
		err = fmt.Errorf("could not verify ingress host: %w", err)
	} else if !isValid {
		err = fmt.Errorf("Ingress host must begin with a protocol, either http:// or https://")
	}

	return err
}

func setIngressHost(ctx context.Context, opts *RuntimeInstallOptions) error {
	var foundIngressHost string
	var foundHostName string

	log.G(ctx).Info("Retrieving ingress controller info from your cluster...\n")

	cs := opts.KubeFactory.KubernetesClientSetOrDie()
	servicesList, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ingress controller info from your cluster: %w", err)
	}

	for _, s := range servicesList.Items {
		if s.ObjectMeta.Name == opts.IngressController.Name() && s.Spec.Type == "LoadBalancer" {
			if len(s.Status.LoadBalancer.Ingress) > 0 {
				ingress := s.Status.LoadBalancer.Ingress[0]
				if ingress.Hostname != "" {
					foundHostName = ingress.Hostname
					break
				} else {
					foundHostName = ingress.IP
					break
				}
			}
		}
	}

	if foundHostName != "" {
		foundIngressHost = fmt.Sprintf("https://%s", foundHostName)
	}

	if store.Get().Silent {
		if foundIngressHost == "" {
			return fmt.Errorf("please provide an ingress host via --ingress-host or installation wizard")
		}
		opts.IngressHost = foundIngressHost
	} else {
		opts.IngressHost, err = getIngressHostFromUserInput(foundIngressHost)
	}

	return err
}

func getIngressHostFromUserInput(foundIngressHost string) (string, error) {
	ingressHostInput, err := getValueFromUserInput("Ingress host", foundIngressHost, validateIngressHost)
	if err != nil {
		return "", err
	}

	return ingressHostInput, nil
}

func checkIngressHostCertificate(ingress string) (bool, error) {
	match, err := regexp.MatchString("http:", ingress)
	if err != nil {
		return false, err
	}
	if match {
		return true, nil
	}

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
	ok6 := strings.Contains(urlErr.Err.Error(), "x509")

	certErr := ok1 || ok2 || ok3 || ok4 || ok5 || ok6
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
	req, err := http.NewRequest(http.MethodGet, ingress, nil)
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
		return fmt.Errorf("cancelled installation due to invalid ingress host certificate. you can try again with --insecure-ingress-host")
	}

	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	log.G(ctx).Warnf("The ingress host does not have a valid certificate.")
	labelStr := fmt.Sprintf("%vDo you wish to continue with the installation in insecure mode with this ingress host?%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"Yes", "Cancel installation"},
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return err
	}

	if result == "Yes" {
		store.Get().InsecureIngressHost = true
	} else {
		return errUserCanceledInsecureInstall
	}

	return nil
}

type Callback func() error

func handleValidationFailsWithRepeat(callback Callback) {
	var err error
	for {
		err = callback()
		if !isValidationError(err) {
			break
		}
	}
}

func isValidationError(err error) bool {
	return err != nil &&
		err != promptui.ErrInterrupt &&
		err != errUserCanceledInsecureInstall
}

func getIscRepo(ctx context.Context) (string, error) {
	currentUser, err := cfConfig.NewClient().V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get current user from platform: %w", err)
	}

	if currentUser.ActiveAccount.SharedConfigRepo == nil {
		return "", nil
	}

	return *currentUser.ActiveAccount.SharedConfigRepo, nil
}

func suggestIscRepo(ctx context.Context, suggestedSharedConfigRepo string) (string, error) {
	setIscRepoResponse, err := cfConfig.NewClient().V2().Runtime().SetSharedConfigRepo(ctx, suggestedSharedConfigRepo)
	if err != nil {
		return "", fmt.Errorf("failed to set shared config repo. Error: %w", err)
	}

	return setIscRepoResponse, nil
}

func isRuntimeManaged(ctx context.Context, runtimeName string) (bool, error) {
	rt, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
	if err != nil {
		return false, fmt.Errorf("failed to get runtime from platform. error: %w", err)
	}

	return rt.Managed, nil
}

func ensureRuntimeOnKubeContext(ctx context.Context, kubeconfig string, runtimeName string, kubeContextName string) error {
	rt, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
	if err != nil {
		return fmt.Errorf("failed to get runtime from platform. error: %w", err)
	}

	runtimeClusterServer := rt.Cluster

	kubeContextServer, err := util.KubeServerByContextName(kubeContextName, kubeconfig)
	if err != nil {
		return err
	}

	// in case Cluster field does not exist on runtime
	// this is a temp solution. need to figure out why runtime is deleted from platform when uninstall fails
	if runtimeClusterServer == nil {
		return fmt.Errorf("failed to verify runtime is installed on the selected kubernetes context. you can use --force to bypass this check")
	}

	if *runtimeClusterServer != kubeContextServer {
		return fmt.Errorf("runtime '%s' does not exist on context '%s'. Make sure you are providing the right kube context or use --force to bypass this check", runtimeName, kubeContextName)
	}

	return nil
}
