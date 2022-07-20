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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/reporter"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	cdutil "github.com/codefresh-io/cli-v2/pkg/util/cd"
	eventsutil "github.com/codefresh-io/cli-v2/pkg/util/events"
	ingressutil "github.com/codefresh-io/cli-v2/pkg/util/ingress"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"
	oc "github.com/codefresh-io/cli-v2/pkg/util/openshift"

	"github.com/Masterminds/semver/v3"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	aev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	apmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model/app-proxy"
	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5/memfs"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/juju/ansiterm"
	"github.com/manifoldco/promptui"
	"github.com/rkrmr33/checklist"
	"github.com/spf13/cobra"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kusttypes "sigs.k8s.io/kustomize/api/types"
	kustid "sigs.k8s.io/kustomize/kyaml/resid"
)

type (
	RuntimeInstallOptions struct {
		RuntimeName                    string
		RuntimeToken                   string
		RuntimeStoreIV                 string
		HostName                       string
		InternalHostName               string
		IngressHost                    string
		IngressClass                   string
		InternalIngressHost            string
		IngressController              ingressutil.IngressController
		Insecure                       bool
		InstallDemoResources           bool
		SkipClusterChecks              bool
		DisableRollback                bool
		DisableTelemetry               bool
		FromRepo                       bool
		Version                        *semver.Version
		GsCloneOpts                    *apgit.CloneOptions
		InsCloneOpts                   *apgit.CloneOptions
		GitIntegrationCreationOpts     *apmodel.AddGitIntegrationArgs
		GitIntegrationRegistrationOpts *apmodel.RegisterToGitIntegrationArgs
		KubeFactory                    kube.Factory
		CommonConfig                   *runtime.CommonConfig
		NamespaceLabels                map[string]string
		SuggestedSharedConfigRepo      string
		InternalIngressAnnotation      map[string]string
		ExternalIngressAnnotation      map[string]string
		EnableGitProviders             bool

		versionStr  string
		kubeContext string
		kubeconfig  string
		gitProvider cfgit.Provider
		branch      string
	}
)

func NewRuntimeInstallCommand() *cobra.Command {
	var (
		gitIntegrationApiURL = ""
		installationOpts     = &RuntimeInstallOptions{
			GitIntegrationCreationOpts: &apmodel.AddGitIntegrationArgs{
				SharingPolicy: apmodel.SharingPolicyAllUsersInAccount,
				APIURL:        &gitIntegrationApiURL,
			},
			GitIntegrationRegistrationOpts: &apmodel.RegisterToGitIntegrationArgs{},
		}
		finalParameters map[string]string
	)

	cmd := &cobra.Command{
		Use:   "install [runtime_name]",
		Short: "Install a new Codefresh runtime",
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export GIT_TOKEN=<token>

# or with the flag:

		--git-token <token>

# Adds a new runtime

	<BIN> runtime install runtime-name --repo gitops_repo
`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				installationOpts.RuntimeName = args[0]
			}

			createAnalyticsReporter(cmd.Context(), reporter.InstallFlow, installationOpts.DisableTelemetry)

			err := runtimeInstallCommandPreRunHandler(cmd, installationOpts)
			handleCliStep(reporter.InstallPhasePreCheckFinish, "Finished pre installation checks", err, true, false)
			if err != nil {
				if errors.Is(err, promptui.ErrInterrupt) {
					return fmt.Errorf("installation canceled by user")
				}

				return util.DecorateErrorWithDocsLink(fmt.Errorf("pre installation error: %w", err), store.Get().RequirementsLink)
			}

			finalParameters = map[string]string{
				"Codefresh context":         cfConfig.CurrentContext,
				"Kube context":              installationOpts.kubeContext,
				"Runtime name":              installationOpts.RuntimeName,
				"Repository URL":            installationOpts.InsCloneOpts.Repo,
				"Ingress host":              installationOpts.IngressHost,
				"Ingress class":             installationOpts.IngressClass,
				"Installing demo resources": strconv.FormatBool(installationOpts.InstallDemoResources),
			}

			if installationOpts.InternalIngressHost != "" {
				finalParameters["Internal ingress host"] = installationOpts.InternalIngressHost
			}

			if err := getApprovalFromUser(cmd.Context(), finalParameters, "runtime install"); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runRuntimeInstall(cmd.Context(), installationOpts)
			handleCliStep(reporter.InstallPhaseFinish, "Runtime installation phase finished", err, false, false)
			return err
		},
	}

	cmd.Flags().StringVar(&installationOpts.IngressHost, "ingress-host", "", "The ingress host")
	cmd.Flags().StringVar(&installationOpts.IngressClass, "ingress-class", "", "The ingress class name")
	cmd.Flags().StringVar(&installationOpts.InternalIngressHost, "internal-ingress-host", "", "The internal ingress host (by default the external ingress will be used for both internal and external traffic)")
	cmd.Flags().StringVar(&installationOpts.GitIntegrationRegistrationOpts.Token, "personal-git-token", "", "The Personal git token for your user")
	cmd.Flags().StringVar(&installationOpts.versionStr, "version", "", "The runtime version to install (default: latest)")
	cmd.Flags().StringVar(&installationOpts.SuggestedSharedConfigRepo, "shared-config-repo", "", "URL to the shared configurations repo. (default: <installation-repo> or the existing one for this account)")
	cmd.Flags().BoolVar(&installationOpts.InstallDemoResources, "demo-resources", true, "Installs demo resources (default: true)")
	cmd.Flags().BoolVar(&installationOpts.SkipClusterChecks, "skip-cluster-checks", false, "Skips the cluster's checks")
	cmd.Flags().BoolVar(&installationOpts.DisableRollback, "disable-rollback", false, "If true, will not perform installation rollback after a failed installation")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be ready")
	cmd.Flags().StringVar(&gitIntegrationApiURL, "provider-api-url", "", "Git provider API url")
	cmd.Flags().BoolVar(&store.Get().SkipIngress, "skip-ingress", false, "Skips the creation of ingress resources")
	cmd.Flags().BoolVar(&store.Get().BypassIngressClassCheck, "bypass-ingress-class-check", false, "Disables the ingress class check during pre-installation")
	cmd.Flags().BoolVar(&installationOpts.DisableTelemetry, "disable-telemetry", false, "If true, will disable the analytics reporting for the installation process")
	cmd.Flags().BoolVar(&store.Get().SetDefaultResources, "set-default-resources", false, "If true, will set default requests and limits on all of the runtime components")
	cmd.Flags().BoolVar(&installationOpts.FromRepo, "from-repo", false, "Installs a runtime from an existing repo. Used for recovery after cluster failure")
	cmd.Flags().StringToStringVar(&installationOpts.NamespaceLabels, "namespace-labels", nil, "Optional labels that will be set on the namespace resource. (e.g. \"key1=value1,key2=value2\"")
	cmd.Flags().StringToStringVar(&installationOpts.InternalIngressAnnotation, "internal-ingress-annotation", nil, "Add annotations to the internal ingress")
	cmd.Flags().StringToStringVar(&installationOpts.ExternalIngressAnnotation, "external-ingress-annotation", nil, "Add annotations to the external ingress")
	cmd.Flags().BoolVar(&installationOpts.EnableGitProviders, "enable-git-providers", false, "Enable git providers (bitbucket-server|gitlab)")
	cmd.Flags().StringVar(&installationOpts.branch, "branch", "", "Install runtime from a specific branch (dev-time only)")

	installationOpts.InsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
		CloneForWrite:    true,
	})

	installationOpts.GsCloneOpts = &apgit.CloneOptions{
		FS:               fs.Create(memfs.New()),
		CreateIfNotExist: true,
	}

	installationOpts.KubeFactory = kube.AddFlags(cmd.Flags())
	installationOpts.kubeconfig = cmd.Flag("kubeconfig").Value.String()

	util.Die(cmd.Flags().MarkHidden("bypass-ingress-class-check"))
	util.Die(cmd.Flags().MarkHidden("enable-git-providers"))
	util.Die(cmd.Flags().MarkHidden("branch"))

	return cmd
}

func runtimeInstallCommandPreRunHandler(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	var err error
	ctx := cmd.Context()

	handleCliStep(reporter.InstallPhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.Version, err = getVersionIfExists(opts.versionStr)
	handleCliStep(reporter.InstallStepPreCheckValidateRuntimeVersion, "Validating runtime version", err, true, false)
	if err != nil {
		return err
	}

	if opts.RuntimeName == "" {
		if !store.Get().Silent {
			opts.RuntimeName, err = getRuntimeNameFromUserInput()
		} else {
			err = fmt.Errorf("must enter a runtime name")
		}
	}
	handleCliStep(reporter.InstallStepPreCheckGetRuntimeName, "Getting runtime name", err, true, false)
	if err != nil {
		return err
	}

	err = validateRuntimeName(opts.RuntimeName)
	handleCliStep(reporter.InstallStepPreCheckRuntimeNameValidation, "Validating runtime name", err, true, false)
	if err != nil {
		return err
	}

	opts.kubeContext, err = getKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
	handleCliStep(reporter.InstallStepPreCheckGetKubeContext, "Getting kube context name", err, true, false)
	if err != nil {
		return err
	}

	err = ensureIngressClass(ctx, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureIngressClass, "Getting ingress class", err, true, false)
	if err != nil {
		return err
	}

	err = getIngressHost(ctx, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureIngressHost, "Getting ingressHost", err, true, false)
	if err != nil {
		return err
	}

	if err = ensureGitData(cmd, opts); err != nil {
		return err
	}

	err = askUserIfToInstallDemoResources(cmd, &opts.InstallDemoResources)
	handleCliStep(reporter.InstallStepPreCheckShouldInstallDemoResources, "Asking user is demo resources should be installed", err, true, false)
	if err != nil {
		return err
	}

	initializeGitSourceCloneOpts(opts)

	opts.InsCloneOpts.Parse()
	opts.GsCloneOpts.Parse()

	if err := ensureGitIntegrationOpts(opts); err != nil {
		return err
	}

	if opts.FromRepo {
		if err := getInstallationFromRepoApproval(ctx, opts); err != nil {
			return err
		}
	}

	if opts.SuggestedSharedConfigRepo != "" {
		sharedConfigRepo, err := setIscRepo(ctx, opts.SuggestedSharedConfigRepo)
		if err != nil {
			return fmt.Errorf("failed to ensure shared config repo: %w", err)
		}

		log.G(ctx).Infof("using repo '%s' as shared config repo for this account", sharedConfigRepo)
	}

	opts.Insecure = true // installs argo-cd in insecure mode, we need this so that the eventsource can talk to the argocd-server with http
	opts.CommonConfig = &runtime.CommonConfig{CodefreshBaseURL: cfConfig.GetCurrentContext().URL}

	return nil
}

func ensureGitData(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	var err error
	ctx := cmd.Context()

	err = ensureRepo(cmd, opts.RuntimeName, opts.InsCloneOpts, false)
	handleCliStep(reporter.InstallStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	opts.gitProvider, err = cfgit.GetProvider(cfgit.ProviderType(opts.InsCloneOpts.Provider), opts.InsCloneOpts.Repo)
	if err != nil {
		return err
	}

	if opts.gitProvider.Type() != cfgit.GITHUB_CLOUD && !opts.EnableGitProviders {
		return fmt.Errorf("Unsupported git provider type %s", opts.gitProvider.Type())
	}

	opts.InsCloneOpts.Provider = string(opts.gitProvider.Type())
	err = getGitToken(cmd, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	err = ensureGitPAT(ctx, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureGitPAT, "Getting git personal access token", err, true, false)
	if err != nil {
		return err
	}

	return nil
}

func getIngressHost(ctx context.Context, opts *RuntimeInstallOptions) error {
	var err error

	if store.Get().Silent {
		err = ensureIngressHost(ctx, opts)
	} else {
		handleValidationFailsWithRepeat(func() error {
			err = ensureIngressHost(ctx, opts)
			if isValidationError(err) {
				fmt.Println("Could not resolve the URL for ingress host; enter a valid URL")
				return err
			}
			return nil
		})
	}
	return err
}

func getGitToken(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	var err error

	if store.Get().Silent {
		err = ensureGitToken(cmd, opts.gitProvider, opts.InsCloneOpts)
	} else {
		handleValidationFailsWithRepeat(func() error {
			err = ensureGitToken(cmd, opts.gitProvider, opts.InsCloneOpts)
			if isValidationError(err) {
				fmt.Println(err)
				return err
			}
			return nil
		})
	}
	return err
}

func ensureIngressHost(ctx context.Context, opts *RuntimeInstallOptions) error {
	if opts.IngressHost == "" { // ingress host not provided by flag
		if err := setIngressHost(ctx, opts); err != nil {
			return err
		}
	}

	if err := parseHostName(opts.IngressHost, &opts.HostName); err != nil {
		return err
	}

	if opts.InternalIngressHost != "" {
		if err := parseHostName(opts.InternalIngressHost, &opts.InternalHostName); err != nil {
			return err
		}
	}

	log.G(ctx).Infof("Using ingress host: %s", opts.IngressHost)

	if !opts.SkipClusterChecks {
		return nil
	}

	log.G(ctx).Info("Validating ingress host")

	if opts.InternalIngressHost != "" {
		if err := validateIngressHostCertificate(ctx, opts.InternalIngressHost); err != nil {
			return err
		}
		log.G(ctx).Infof("Using internal ingress host: %s", opts.InternalIngressHost)
	}

	return validateIngressHostCertificate(ctx, opts.IngressHost)
}

func parseHostName(ingressHost string, hostName *string) error {
	parsed, err := url.Parse(ingressHost)
	if err != nil {
		return err
	}

	isIP := util.IsIP(parsed.Host)
	if !isIP {
		*hostName, _, err = net.SplitHostPort(parsed.Host)
		if err != nil {
			if err.Error() == fmt.Sprintf("address %s: missing port in address", parsed.Host) {
				*hostName = parsed.Host
			} else {
				return err
			}
		}
	}

	return nil
}

func validateIngressHostCertificate(ctx context.Context, ingressHost string) error {
	certValid, err := checkIngressHostCertificate(ingressHost)
	if err != nil {
		log.G(ctx).Fatalf("failed to check ingress host: %v", err)
	}

	if !certValid {
		if err = askUserIfToProceedWithInsecure(ctx); err != nil {
			return err
		}
	}

	return nil
}

func ensureIngressClass(ctx context.Context, opts *RuntimeInstallOptions) error {
	if store.Get().BypassIngressClassCheck || store.Get().SkipIngress {
		opts.IngressController = ingressutil.GetController("")
		return nil
	}

	log.G(ctx).Info("Retrieving ingress class info from your cluster...\n")

	cs := opts.KubeFactory.KubernetesClientSetOrDie()
	ingressClassList, err := cs.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ingress class list from your cluster: %w", err)
	}

	var ingressClassNames []string
	ingressClassNameToController := make(map[string]ingressutil.IngressController)
	var isValidClass bool

	for _, ic := range ingressClassList.Items {
		for _, controller := range ingressutil.SupportedControllers {
			if ic.Spec.Controller == string(controller) {
				ingressClassNames = append(ingressClassNames, ic.Name)
				ingressClassNameToController[ic.Name] = ingressutil.GetController(string(controller))

				if opts.IngressClass == ic.Name { //if ingress class provided via flag
					isValidClass = true
				}
				break
			}
		}
	}

	if opts.IngressClass != "" { //if ingress class provided via flag
		if !isValidClass {
			return fmt.Errorf("ingress class '%s' is not supported", opts.IngressClass)
		}
	} else if len(ingressClassNames) == 0 {
		return fmt.Errorf("no ingress classes of the supported types were found")
	} else if len(ingressClassNames) == 1 {
		log.G(ctx).Info("Using ingress class: ", ingressClassNames[0])
		opts.IngressClass = ingressClassNames[0]
	} else if len(ingressClassNames) > 1 {
		if !store.Get().Silent {
			opts.IngressClass, err = getIngressClassFromUserSelect(ingressClassNames)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("there are multiple ingress controllers on your cluster, please add the --ingress-class flag and define its value")
		}
	}

	opts.IngressController = ingressClassNameToController[opts.IngressClass]

	if opts.IngressController.Name() == string(ingressutil.IngressControllerNginxEnterprise) {
		log.G(ctx).Warn("You are using the NGINX enterprise edition (nginx.org/ingress-controller) as your ingress controller. To successfully install the runtime, configure all required settings, as described in : ", store.Get().RequirementsLink)
	}

	return nil
}

func getComponents(rt *runtime.Runtime, opts *RuntimeInstallOptions) []string {
	var componentNames []string
	for _, component := range rt.Spec.Components {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, component.Name)
		componentNames = append(componentNames, componentFullName)
	}

	//  should find a more dynamic way to get these additional components
	additionalComponents := []string{"events-reporter", "workflow-reporter", "rollout-reporter"}
	for _, additionalComponentName := range additionalComponents {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, additionalComponentName)
		componentNames = append(componentNames, componentFullName)
	}
	argoCDFullName := store.Get().ArgoCD
	componentNames = append(componentNames, argoCDFullName)

	return componentNames
}

func createRuntimeOnPlatform(ctx context.Context, opts *model.RuntimeInstallationArgs) (string, string, error) {
	runtimeCreationResponse, err := cfConfig.NewClient().V2().Runtime().Create(ctx, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to create a new runtime: %s. Error: %w", opts.RuntimeName, err)
	}

	const IV_LENGTH = 16
	iv := make([]byte, IV_LENGTH)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create an initialization vector: %s. Error: %w", opts.RuntimeName, err)
	}

	return runtimeCreationResponse.NewAccessToken, hex.EncodeToString(iv), nil
}

func runRuntimeInstall(ctx context.Context, opts *RuntimeInstallOptions) error {
	rt, err := preInstallationChecks(ctx, opts)
	handleCliStep(reporter.InstallPhaseRunPreCheckFinish, "Pre run installation checks", err, true, true)
	if err != nil {
		return fmt.Errorf("pre installation checks failed: %w", err)
	}

	handleCliStep(reporter.InstallPhaseStart, "Runtime installation phase started", nil, false, true)

	server, err := util.KubeServerByContextName(opts.kubeContext, opts.kubeconfig)
	handleCliStep(reporter.InstallStepGetServerAddress, "Getting kube server address", err, false, true)
	if err != nil {
		return fmt.Errorf("failed to get current server address: %w", err)
	}

	runtimeVersion := rt.Spec.Version.String()

	componentNames := getComponents(rt, opts)

	if opts.FromRepo {
		// in case of a runtime recovery, we don't want to clear the repo when failure occures
		opts.DisableRollback = true
	}

	defer func() {
		// will rollback if err is not nil and it is safe to do so
		postInstallationHandler(ctx, opts, err, &opts.DisableRollback)
	}()

	ingressControllerName := opts.IngressController.Name()

	token, iv, err := createRuntimeOnPlatform(ctx, &model.RuntimeInstallationArgs{
		RuntimeName:         opts.RuntimeName,
		Cluster:             server,
		RuntimeVersion:      runtimeVersion,
		IngressHost:         &opts.IngressHost,
		InternalIngressHost: &opts.InternalIngressHost,
		IngressClass:        &opts.IngressClass,
		IngressController:   &ingressControllerName,
		ComponentNames:      componentNames,
		Repo:                &opts.InsCloneOpts.Repo,
		Recover:             &opts.FromRepo,
	})
	handleCliStep(reporter.InstallStepCreateRuntimeOnPlatform, "Creating runtime on platform", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create a new runtime: %w", err))
	}

	opts.RuntimeToken = token
	opts.RuntimeStoreIV = iv
	rt.Spec.Cluster = server
	rt.Spec.IngressHost = opts.IngressHost
	rt.Spec.IngressClass = opts.IngressClass
	rt.Spec.InternalIngressHost = opts.InternalIngressHost
	rt.Spec.IngressController = string(opts.IngressController.Name())
	rt.Spec.Repo = opts.InsCloneOpts.Repo

	appSpecifier := rt.Spec.FullSpecifier()

	if opts.FromRepo {
		// installing argocd with manifests from the provided repo
		appSpecifier = opts.InsCloneOpts.Repo + "/bootstrap/argo-cd"
	}

	log.G(ctx).WithField("version", rt.Spec.Version).Infof("Installing runtime \"%s\"", opts.RuntimeName)
	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier:    appSpecifier,
		Namespace:       opts.RuntimeName,
		KubeFactory:     opts.KubeFactory,
		CloneOptions:    opts.InsCloneOpts,
		Insecure:        opts.Insecure,
		Recover:         opts.FromRepo,
		KubeContextName: opts.kubeContext,
		Timeout:         store.Get().WaitTimeout,
		ArgoCDLabels: map[string]string{
			store.Get().LabelKeyCFType:     store.Get().CFComponentType,
			store.Get().LabelKeyCFInternal: "true",
		},
		BootstrapAppsLabels: map[string]string{
			store.Get().LabelKeyCFInternal: "true",
		},
		NamespaceLabels: opts.NamespaceLabels,
	})
	handleCliStep(reporter.InstallStepBootstrapRepo, "Bootstrapping repository", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to bootstrap repository: %w", err))
	}

	err = oc.PrepareOpenshiftCluster(ctx, &oc.OpenshiftOptions{
		KubeFactory:  opts.KubeFactory,
		RuntimeName:  opts.RuntimeName,
		InsCloneOpts: opts.InsCloneOpts,
	})
	if err != nil {
		return fmt.Errorf("failed setting up environment for openshift %w", err)
	}

	if !opts.FromRepo {
		err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
			CloneOpts:   opts.InsCloneOpts,
			ProjectName: opts.RuntimeName,
			Labels: map[string]string{
				store.Get().LabelKeyCFType:     fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFType)),
				store.Get().LabelKeyCFInternal: fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFInternal)),
			},
			Annotations: map[string]string{
				store.Get().AnnotationKeySyncWave: fmt.Sprintf("{{ annotations.%s }}", util.EscapeAppsetFieldName(store.Get().AnnotationKeySyncWave)),
			},
		})
	}
	handleCliStep(reporter.InstallStepCreateProject, "Creating Project", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create project: %w", err))
	}

	// persists codefresh-cm, this must be created before events-reporter eventsource
	// otherwise it will not start and no events will get to the platform.
	if !opts.FromRepo {
		err = persistRuntime(ctx, opts.InsCloneOpts, rt, opts.CommonConfig)
	} else {
		// in case of runtime recovery we only update the existing cm
		err = updateCodefreshCM(ctx, opts, rt, server)
	}
	handleCliStep(reporter.InstallStepCreateOrUpdateConfigMap, "Creating/Updating codefresh-cm", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create or update codefresh-cm: %w", err))
	}

	err = applySecretsToCluster(ctx, opts)
	handleCliStep(reporter.InstallStepApplySecretsToCluster, "Applying secrets to cluster", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to apply secrets to cluster: %w", err))
	}

	err = createRuntimeComponents(ctx, opts, rt)
	if err != nil {
		return err
	}

	err = createGitSources(ctx, opts)
	if err != nil {
		return err
	}

	timeoutErr := intervalCheckIsRuntimePersisted(ctx, opts.RuntimeName)
	handleCliStep(reporter.InstallStepCompleteRuntimeInstallation, "Wait for runtime sync", timeoutErr, false, true)

	// if we got to this point the runtime was installed successfully
	// thus we shall not perform a rollback after this point.
	opts.DisableRollback = true

	if store.Get().SkipIngress {
		handleCliStep(reporter.InstallStepCreateDefaultGitIntegration, "-skipped-", err, false, true)
		handleCliStep(reporter.InstallStepRegisterToDefaultGitIntegration, "-skipped-", err, false, true)

		var apiURL string
		if opts.GitIntegrationCreationOpts.APIURL != nil {
			apiURL = fmt.Sprintf("--api-url %s", *opts.GitIntegrationCreationOpts.APIURL)
		}

		skipIngressInfoMsg := util.Doc(fmt.Sprintf(`
To complete the installation: 
1. Configure your cluster's routing service with path to '/%s' and \"%s\"
2. Create and register Git integration using the commands:

<BIN> integration git add default --runtime %s %s --provider %s

<BIN> integration git register default --runtime %s --token <AUTHENTICATION_TOKEN>
`,
			store.Get().AppProxyIngressPath,
			util.GenerateIngressEventSourcePath(opts.RuntimeName),
			opts.RuntimeName,
			apiURL,
			opts.GitIntegrationCreationOpts.Provider,
			opts.RuntimeName))
		summaryArr = append(summaryArr, summaryLog{skipIngressInfoMsg, Info})
	} else {
		gitIntegrationErr := intervalCheckIsGitIntegrationCreated(ctx, opts)
		if gitIntegrationErr != nil {
			return gitIntegrationErr
		}
	}

	installationSuccessMsg := fmt.Sprintf("Runtime \"%s\" installed successfully", opts.RuntimeName)
	if timeoutErr != nil {
		installationSuccessMsg = fmt.Sprintf("Runtime \"%s\" installed with some issues", opts.RuntimeName)
	}

	summaryArr = append(summaryArr, summaryLog{installationSuccessMsg, Info})
	return nil
}

func createRuntimeComponents(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	var err error

	if !opts.FromRepo {
		for _, component := range rt.Spec.Components {
			infoStr := fmt.Sprintf("Creating component \"%s\"", component.Name)
			log.G(ctx).Infof(infoStr)
			component.IsInternal = true
			err = component.CreateApp(ctx, opts.KubeFactory, opts.InsCloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", "")
			if err != nil {
				err = util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\" application: %w", component.Name, err))
				break
			}
		}
	}

	handleCliStep(reporter.InstallStepCreateComponents, "Creating components", err, false, true)
	if err != nil {
		return err
	}

	if opts.IngressController.Name() == string(ingressutil.IngressControllerNginxEnterprise) && !opts.FromRepo {
		err := createMasterIngressResource(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to create master ingress resource: %w", err)
		}
	}

	if !opts.FromRepo {
		err = installComponents(ctx, opts, rt)
	}
	handleCliStep(reporter.InstallStepInstallComponenets, "Installing components", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to install components: %s", err))
	}

	return nil
}

func createMasterIngressResource(ctx context.Context, opts *RuntimeInstallOptions) error {
	if store.Get().SkipIngress {
		return nil
	}

	r, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	ingressOptions := ingressutil.CreateIngressOptions{
		Name:             opts.RuntimeName + store.Get().MasterIngressName,
		Namespace:        opts.RuntimeName,
		IngressClassName: opts.IngressClass,
		Host:             opts.HostName,
		Annotations: map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
		},
	}

	if opts.ExternalIngressAnnotation != nil {
		mergeAnnotations(ingressOptions.Annotations, opts.ExternalIngressAnnotation)
	}

	ingress := ingressutil.CreateIngress(&ingressOptions)

	if err = fs.WriteYamls(fs.Join(store.Get().InClusterPath, "master-ingress.yaml"), ingress); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Master Ingress Manifest")

	return apu.PushWithMessage(ctx, r, "Created master ingress resource")
}

func createGitSources(ctx context.Context, opts *RuntimeInstallOptions) error {
	var err error
	var gitSrcMessage string
	var createGitSrcMessgae string

	if !opts.FromRepo {
		gitSrcMessage = fmt.Sprintf("Creating git source \"%s\"", store.Get().GitSourceName)
		err = RunGitSourceCreate(ctx, &GitSourceCreateOptions{
			InsCloneOpts:        opts.InsCloneOpts,
			GsCloneOpts:         opts.GsCloneOpts,
			GsName:              store.Get().GitSourceName,
			RuntimeName:         opts.RuntimeName,
			CreateDemoResources: opts.InstallDemoResources,
			HostName:            opts.HostName,
			IngressHost:         opts.IngressHost,
			IngressClass:        opts.IngressClass,
			IngressController:   opts.IngressController,
			Flow:                store.Get().InstallationFlow,
		})
	}
	handleCliStep(reporter.InstallStepCreateGitsource, gitSrcMessage, err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\": %w", store.Get().GitSourceName, err))
	}

	if !opts.FromRepo {
		if opts.gitProvider.SupportsMarketplace() {
			mpCloneOpts := &apgit.CloneOptions{
				Repo: store.Get().MarketplaceRepo,
				FS:   fs.Create(memfs.New()),
			}
			mpCloneOpts.Parse()

			createGitSrcMessgae = fmt.Sprintf("Creating %s", store.Get().MarketplaceGitSourceName)

			err = RunGitSourceCreate(ctx, &GitSourceCreateOptions{
				InsCloneOpts:        opts.InsCloneOpts,
				GsCloneOpts:         mpCloneOpts,
				GsName:              store.Get().MarketplaceGitSourceName,
				RuntimeName:         opts.RuntimeName,
				CreateDemoResources: false,
				Exclude:             "**/images/**/*",
				Include:             "workflows/**/*.yaml",
				Flow:                store.Get().InstallationFlow,
			})
		} else {
			createGitSrcMessgae = fmt.Sprintf("Skipping %s with git provider %s", store.Get().MarketplaceGitSourceName, opts.gitProvider.Type())
		}
	}
	handleCliStep(reporter.InstallStepCreateMarketplaceGitsource, createGitSrcMessgae, err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\": %w", store.Get().MarketplaceGitSourceName, err))
	}

	return nil
}

func createGitIntegration(ctx context.Context, opts *RuntimeInstallOptions) error {
	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client while creating git integration: %w", err)
	}

	err = addDefaultGitIntegration(ctx, appProxyClient, opts.RuntimeName, opts.GitIntegrationCreationOpts)
	handleCliStep(reporter.InstallStepCreateDefaultGitIntegration, "Creating a default git integration", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create default git integration: %w", err))
	}

	err = registerUserToGitIntegration(ctx, appProxyClient, opts.RuntimeName, opts.GitIntegrationRegistrationOpts)
	handleCliStep(reporter.InstallStepRegisterToDefaultGitIntegration, "Registering user to the default git integration", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to register user to the default git integration: %w", err))
	}

	return nil
}

func intervalCheckIsGitIntegrationCreated(ctx context.Context, opts *RuntimeInstallOptions) error {
	maxRetries := 6 // up to a minute
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	_, cancel := context.WithCancel(ctx)
	defer cancel()

	for triesLeft := maxRetries; triesLeft > 0; triesLeft-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		err := createGitIntegration(ctx, opts)
		if err != nil {
			if err == ctx.Err() {
				return ctx.Err()
			}

			log.G(ctx).Debugf("Retrying to create the default git integration. Error: %s", err.Error())
		} else {
			return nil
		}
	}

	return fmt.Errorf("timed ot while waiting for git integration to be created")
}

func addDefaultGitIntegration(ctx context.Context, appProxyClient codefresh.AppProxyAPI, runtime string, opts *apmodel.AddGitIntegrationArgs) error {
	if err := RunGitIntegrationAddCommand(ctx, appProxyClient, opts); err != nil {
		var apiURL string
		if opts.APIURL != nil {
			apiURL = fmt.Sprintf("--api-url %s", *opts.APIURL)
		}

		commandAdd := util.Doc(fmt.Sprintf(
			"\t<BIN> integration git add default --runtime %s --provider %s %s",
			runtime,
			strings.ToLower(opts.Provider.String()),
			apiURL,
		))

		commandRegister := util.Doc(fmt.Sprintf(
			"\t<BIN> integration git register default --runtime %s --token <your-token>",
			runtime,
		))

		return fmt.Errorf(`
		%w
you can try to create it manually by running:

		%s
		%s
		`,
			err,
			commandAdd,
			commandRegister,
		)
	}

	log.G(ctx).Info("Added default git integration")
	return nil
}

func registerUserToGitIntegration(ctx context.Context, appProxyClient codefresh.AppProxyAPI, runtime string, opts *apmodel.RegisterToGitIntegrationArgs) error {
	if err := RunGitIntegrationRegisterCommand(ctx, appProxyClient, opts); err != nil {
		command := util.Doc(fmt.Sprintf(
			"\t<BIN> integration git register default --runtime %s --token %s",
			runtime,
			opts.Token,
		))
		return fmt.Errorf(`
%w
you can try to create it manually by running:

%s
`,
			err,
			command,
		)
	}

	return nil
}

func installComponents(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	var err error

	if !store.Get().SkipIngress && rt.Spec.IngressController != string(ingressutil.IngressControllerALB) {
		if err = createWorkflowsIngress(ctx, opts, rt); err != nil {
			return fmt.Errorf("failed to patch Argo-Workflows ingress: %w", err)
		}
	}

	if err = configureAppProxy(ctx, opts, rt); err != nil {
		return fmt.Errorf("failed to patch App-Proxy ingress: %w", err)
	}

	if err = createEventsReporter(ctx, opts.InsCloneOpts, opts); err != nil {
		return fmt.Errorf("failed to create events-reporter: %w", err)
	}

	if err = createReporter(
		ctx, opts.InsCloneOpts, opts, reporterCreateOptions{
			reporterName: store.Get().WorkflowReporterName,
			gvr: []gvr{
				{
					resourceName: store.Get().WorkflowResourceName,
					group:        "argoproj.io",
					version:      "v1alpha1",
				},
			},
			saName:     store.Get().CodefreshSA,
			IsInternal: true,
		}); err != nil {
		return fmt.Errorf("failed to create workflows-reporter: %w", err)
	}

	if err = createReporter(ctx, opts.InsCloneOpts, opts, reporterCreateOptions{
		reporterName: store.Get().RolloutReporterName,
		gvr: []gvr{
			{
				resourceName: store.Get().RolloutResourceName,
				group:        "argoproj.io",
				version:      "v1alpha1",
			},
			{
				resourceName: store.Get().ReplicaSetResourceName,
				group:        "apps",
				version:      "v1",
			},
			{
				resourceName: store.Get().AnalysisRunResourceName,
				group:        "argoproj.io",
				version:      "v1alpha1",
			},
		},
		saName:       store.Get().RolloutReporterServiceAccount,
		IsInternal:   true,
		clusterScope: true,
	}); err != nil {
		return fmt.Errorf("failed to create rollout-reporter: %w", err)
	}

	return nil
}

func preInstallationChecks(ctx context.Context, opts *RuntimeInstallOptions) (*runtime.Runtime, error) {
	log.G(ctx).Debug("running pre-installation checks...")

	handleCliStep(reporter.InstallPhaseRunPreCheckStart, "Running pre run installation checks", nil, true, false)

	rt, err := runtime.Download(opts.Version, opts.RuntimeName, opts.branch)
	handleCliStep(reporter.InstallStepRunPreCheckDownloadRuntimeDefinition, "Downloading runtime definition", err, true, true)
	if err != nil {
		return nil, fmt.Errorf("failed to download runtime definition: %w", err)
	}

	if rt.Spec.DefVersion.GreaterThan(store.Get().MaxDefVersion) {
		err = fmt.Errorf("your cli version is out of date. please upgrade to the latest version before installing")
	}
	handleCliStep(reporter.InstallStepRunPreCheckEnsureCliVersion, "Checking CLI version", err, true, false)
	if err != nil {
		return nil, util.DecorateErrorWithDocsLink(err, store.Get().DownloadCliLink)
	}

	err = checkRuntimeCollisions(ctx, opts.KubeFactory, opts.RuntimeName)
	handleCliStep(reporter.InstallStepRunPreCheckRuntimeCollision, "Checking for runtime collisions", err, true, false)
	if err != nil {
		return nil, fmt.Errorf("runtime collision check failed: %w", err)
	}

	if !opts.FromRepo {
		err = checkExistingRuntimes(ctx, opts.RuntimeName)
	}
	handleCliStep(reporter.InstallStepRunPreCheckExisitingRuntimes, "Checking for exisiting runtimes", err, true, false)
	if err != nil {
		return nil, fmt.Errorf("existing runtime check failed: %w", err)
	}

	if !opts.SkipClusterChecks {
		err = kubeutil.EnsureClusterRequirements(ctx, opts.KubeFactory, opts.RuntimeName, cfConfig.GetCurrentContext().URL)
	}
	handleCliStep(reporter.InstallStepRunPreCheckValidateClusterRequirements, "Ensuring cluster requirements", err, true, false)
	if err != nil {
		return nil, fmt.Errorf("validation of minimum cluster requirements failed: %w", err)
	}

	return rt, nil
}

func checkRuntimeCollisions(ctx context.Context, kube kube.Factory, runtime string) error {
	log.G(ctx).Debug("checking for argocd collisions in cluster")

	cs, err := kube.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes clientset: %w", err)
	}

	crb, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, store.Get().ArgoCDServerName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil // no collision
		}

		return fmt.Errorf("failed to get cluster-role-binding \"%s\": %w", store.Get().ArgoCDServerName, err)
	}

	log.G(ctx).Debug("argocd cluster-role-binding found")

	if len(crb.Subjects) == 0 {
		return nil // no collision
	}

	subjNamespace := crb.Subjects[0].Namespace

	if subjNamespace == runtime {
		return nil // argocd will be over-written by runtime installation
	}

	// check if some argocd is actually using this crb
	_, err = cs.AppsV1().Deployments(subjNamespace).Get(ctx, store.Get().ArgoCDServerName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.G(ctx).Debug("argocd cluster-role-binding subject does not exist, no collision")

			return nil // no collision
		}

		return fmt.Errorf("failed to get deployment \"%s\": %w", store.Get().ArgoCDServerName, err)
	}

	return fmt.Errorf("argo-cd is already installed on this cluster in namespace \"%s\", you can uninstall it by running '%s runtime uninstall %s --skip-checks --force'", subjNamespace, store.Get().BinaryName, subjNamespace)
}

func checkExistingRuntimes(ctx context.Context, runtime string) error {
	_, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtime)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil // runtime does not exist
		}

		return fmt.Errorf("failed to get runtime: %w", err)
	}

	return fmt.Errorf("runtime \"%s\" already exists", runtime)
}

func printComponentsState(ctx context.Context, runtime string) error {
	components := map[string]model.Component{}
	lock := sync.Mutex{}

	curComponents, err := cfConfig.NewClient().V2().Component().List(ctx, runtime)
	if err != nil {
		return err
	}

	for _, c := range curComponents {
		components[c.Metadata.Name] = c
	}

	// refresh components state
	go func() {
		t := time.NewTicker(2 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			curComponents, err := cfConfig.NewClient().V2().Component().List(ctx, runtime)
			if err != nil && ctx.Err() == nil {
				log.G(ctx).WithError(err).Error("failed to refresh components state")
				continue
			}

			lock.Lock()
			for _, c := range curComponents {
				components[c.Metadata.Name] = c
			}
			lock.Unlock()
		}
	}()

	checkers := make([]checklist.Checker, len(curComponents))
	for i, c := range curComponents {
		name := c.Metadata.Name
		checkers[i] = func(_ context.Context) (checklist.ListItemState, checklist.ListItemInfo) {
			lock.Lock()
			defer lock.Unlock()
			return getComponentChecklistState(components[name])
		}
	}

	log.G().Info("Waiting for the runtime installation to complete...")

	cl := checklist.NewCheckList(
		os.Stdout,
		checklist.ListItemInfo{"COMPONENT", "HEALTH STATUS", "SYNC STATUS", "VERSION", "ERRORS"},
		checkers,
		&checklist.CheckListOptions{
			Interval:     1 * time.Second,
			WaitAllReady: true,
		},
	)

	if err := cl.Start(ctx); err != nil && ctx.Err() == nil {
		return err
	}

	return nil
}

func intervalCheckIsRuntimePersisted(ctx context.Context, runtimeName string) error {
	maxRetries := 48 // up to 8 min
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	subCtx, cancel := context.WithCancel(ctx)

	go func() {
		if err := printComponentsState(subCtx, runtimeName); err != nil {
			log.G(ctx).WithError(err).Error("failed to print components state")
		}
	}()
	defer cancel()

	for triesLeft := maxRetries; triesLeft > 0; triesLeft-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		runtime, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
		if err != nil {
			if err == ctx.Err() {
				return ctx.Err()
			}

			log.G(ctx).Debugf("retrying the call to graphql API. Error: %s", err.Error())
		} else if runtime.InstallationStatus == model.InstallationStatusCompleted {
			return nil
		}
	}

	return fmt.Errorf("timed out while waiting for runtime installation to complete")
}

func RunRuntimeList(ctx context.Context) error {
	runtimes, err := cfConfig.NewClient().V2().Runtime().List(ctx)
	if err != nil {
		return err
	}

	if len(runtimes) == 0 {
		log.G(ctx).Info("No runtimes were found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tVERSION\tSYNC_STATUS\tHEALTH_STATUS\tHEALTH_MESSAGE\tINSTALLATION_STATUS\tINGRESS_HOST\tINGRESS_CLASS")
	if err != nil {
		return err
	}

	for _, rt := range runtimes {
		name := rt.Metadata.Name
		namespace := "N/A"
		cluster := "N/A"
		version := "N/A"
		syncStatus := rt.SyncStatus
		healthStatus := rt.HealthStatus
		healthMessage := "N/A"
		installationStatus := rt.InstallationStatus
		ingressHost := "N/A"
		internalIngressHost := "N/A"
		ingressClass := "N/A"

		if rt.Managed {
			name = fmt.Sprintf("%s (hosted)", rt.Metadata.Name)
		}

		if rt.Metadata.Namespace != nil {
			namespace = *rt.Metadata.Namespace
		}

		if rt.Cluster != nil {
			cluster = *rt.Cluster
		}

		if rt.RuntimeVersion != nil {
			version = *rt.RuntimeVersion
		}

		if rt.HealthMessage != nil {
			healthMessage = *rt.HealthMessage
		}

		if rt.IngressHost != nil {
			ingressHost = *rt.IngressHost
		}

		if rt.InternalIngressHost != nil {
			internalIngressHost = *rt.InternalIngressHost
		}

		if rt.IngressClass != nil {
			ingressClass = *rt.IngressClass
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			version,
			syncStatus,
			healthStatus,
			healthMessage,
			installationStatus,
			ingressHost,
			internalIngressHost,
			ingressClass,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func RunRuntimeUninstall(ctx context.Context, opts *RuntimeUninstallOptions) error {
	defer printSummaryToUser()

	handleCliStep(reporter.UninstallPhaseStart, "Uninstall phase started", nil, false, false)

	// check whether the runtime exists
	var err error
	if !opts.SkipChecks {
		_, err = cfConfig.NewClient().V2().Runtime().Get(ctx, opts.RuntimeName)
	}
	handleCliStep(reporter.UninstallStepCheckRuntimeExists, "Checking if runtime exists", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--skip-checks\" flag", Info})
		return err
	}

	log.G(ctx).Infof("Uninstalling runtime \"%s\" - this process may take a few minutes...", opts.RuntimeName)

	err = removeGitIntegrations(ctx, opts)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveGitIntegrations, "Removing git integrations", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	err = removeRuntimeIsc(ctx, opts.RuntimeName)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveRuntimeIsc, "Removing runtime ISC", err, false, true)
	if err != nil {
		return fmt.Errorf("failed to remove runtime isc: %w", err)
	}

	if !opts.skipAutopilotUninstall {
		subCtx, cancel := context.WithCancel(ctx)
		go func() {
			if err := printApplicationsState(subCtx, opts.RuntimeName, opts.KubeFactory, opts.Managed); err != nil {
				log.G(ctx).WithError(err).Debug("failed to print uninstallation progress")
			}
		}()

		if !opts.Managed {
			err = apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
				Namespace:       opts.RuntimeName,
				KubeContextName: opts.kubeContext,
				Timeout:         opts.Timeout,
				CloneOptions:    opts.CloneOpts,
				KubeFactory:     opts.KubeFactory,
				Force:           opts.Force,
				FastExit:        opts.FastExit,
			})
		}
		cancel() // to tell the progress to stop displaying even if it's not finished
		if opts.Force {
			err = nil
		}
	}
	handleCliStep(reporter.UninstallStepUninstallRepo, "Uninstalling repo", err, false, !opts.Managed && !opts.skipAutopilotUninstall)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	log.G(ctx).Infof("Deleting runtime '%s' from platform", opts.RuntimeName)
	if opts.Managed {
		_, err = cfConfig.NewClient().V2().Runtime().DeleteManaged(ctx, opts.RuntimeName)
	} else {
		err = deleteRuntimeFromPlatform(ctx, opts)
	}
	handleCliStep(reporter.UninstallStepDeleteRuntimeFromPlatform, "Deleting runtime from platform", err, false, !opts.Managed)
	if err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	if cfConfig.GetCurrentContext().DefaultRuntime == opts.RuntimeName {
		cfConfig.GetCurrentContext().DefaultRuntime = ""
	}

	uninstallDoneStr := fmt.Sprintf("Done uninstalling runtime \"%s\"", opts.RuntimeName)
	appendLogToSummary(uninstallDoneStr, nil)

	return nil
}

func persistRuntime(ctx context.Context, cloneOpts *apgit.CloneOptions, rt *runtime.Runtime, rtConf *runtime.CommonConfig) error {
	r, fs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err = rt.Save(fs, fs.Join(apstore.Default.BootsrtrapDir, rt.Name+".yaml"), rtConf); err != nil {
		return err
	}

	if err := updateProject(fs, rt); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing runtime definition to the installation repo")

	return apu.PushWithMessage(ctx, r, "Persisted runtime data")
}

func createWorkflowsIngress(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	r, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	overlaysDir := fs.Join(apstore.Default.AppsDir, store.Get().WorkflowsIngressPath, apstore.Default.OverlaysDir, rt.Name)
	ingressOptions := ingressutil.CreateIngressOptions{
		Name:             rt.Name + store.Get().WorkflowsIngressName,
		Namespace:        rt.Namespace,
		IngressClassName: opts.IngressClass,
		Host:             opts.HostName,
		Annotations: map[string]string{
			"ingress.kubernetes.io/protocol":               "https",
			"ingress.kubernetes.io/rewrite-target":         "/$2",
			"nginx.ingress.kubernetes.io/backend-protocol": "https",
			"nginx.ingress.kubernetes.io/rewrite-target":   "/$2",
		},
		Paths: []ingressutil.IngressPath{
			{
				Path:        fmt.Sprintf("/%s(/|$)(.*)", store.Get().WorkflowsIngressPath),
				PathType:    netv1.PathTypeImplementationSpecific,
				ServiceName: store.Get().ArgoWFServiceName,
				ServicePort: store.Get().ArgoWFServicePort,
			},
		},
	}

	if opts.ExternalIngressAnnotation != nil {
		mergeAnnotations(ingressOptions.Annotations, opts.ExternalIngressAnnotation)
	}

	ingress := ingressutil.CreateIngress(&ingressOptions)
	opts.IngressController.Decorate(ingress)

	if err = fs.WriteYamls(fs.Join(overlaysDir, "ingress.yaml"), ingress); err != nil {
		return err
	}

	if err = billyUtils.WriteFile(fs, fs.Join(overlaysDir, "ingress-patch.json"), workflowsIngressPatch, 0666); err != nil {
		return err
	}

	kust, err := kustutil.ReadKustomization(fs, overlaysDir)
	if err != nil {
		return err
	}

	kust.Resources = append(kust.Resources, "ingress.yaml")
	kust.Patches = append(kust.Patches, kusttypes.Patch{
		Target: &kusttypes.Selector{
			ResId: kustid.ResId{
				Gvk: kustid.Gvk{
					Group:   appsv1.SchemeGroupVersion.Group,
					Version: appsv1.SchemeGroupVersion.Version,
					Kind:    "Deployment",
				},
				Name: store.Get().ArgoWFServiceName,
			},
		},
		Path: "ingress-patch.json",
	})
	if err = kustutil.WriteKustomization(fs, kust, overlaysDir); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Argo Workflows ingress manifests")

	return apu.PushWithMessage(ctx, r, "Created Workflows Ingress")
}

func mergeAnnotations(annotation map[string]string, newAnnotation map[string]string) {
	for key, element := range newAnnotation {
		annotation[key] = element
	}
}

func configureAppProxy(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	r, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	overlaysDir := fs.Join(apstore.Default.AppsDir, "app-proxy", apstore.Default.OverlaysDir, rt.Name)

	kust, err := kustutil.ReadKustomization(fs, overlaysDir)
	if err != nil {
		return err
	}

	literalResources := []string{
		"argoWorkflowsInsecure=true",
		fmt.Sprintf("cfHost=%s", cfConfig.GetCurrentContext().URL),
		fmt.Sprintf("cors=%s", cfConfig.GetCurrentContext().URL),
		"env=production",
	}

	// configure codefresh host
	kust.ConfigMapGenerator = append(kust.ConfigMapGenerator, kusttypes.ConfigMapArgs{
		GeneratorArgs: kusttypes.GeneratorArgs{
			Name:     store.Get().AppProxyServiceName + "-cm",
			Behavior: "merge",
			KvPairSources: kusttypes.KvPairSources{
				LiteralSources: literalResources,
			},
		},
	})

	hostName := opts.HostName
	if opts.InternalHostName != "" {
		hostName = opts.InternalHostName
	}

	if !store.Get().SkipIngress {
		ingressOptions := ingressutil.CreateIngressOptions{
			Name:             rt.Name + store.Get().AppProxyIngressName,
			Namespace:        rt.Namespace,
			IngressClassName: opts.IngressClass,
			Host:             hostName,
			Paths: []ingressutil.IngressPath{
				{
					Path:        store.Get().AppProxyIngressPath,
					PathType:    netv1.PathTypePrefix,
					ServiceName: store.Get().AppProxyServiceName,
					ServicePort: store.Get().AppProxyServicePort,
				},
			},
		}

		if opts.InternalIngressAnnotation != nil {
			ingressOptions.Annotations = make(map[string]string)
			mergeAnnotations(ingressOptions.Annotations, opts.InternalIngressAnnotation)
		}

		ingress := ingressutil.CreateIngress(&ingressOptions)
		opts.IngressController.Decorate(ingress)

		if err = fs.WriteYamls(fs.Join(overlaysDir, "ingress.yaml"), ingress); err != nil {
			return err
		}

		kust.Resources = append(kust.Resources, "ingress.yaml")
	}

	if err = kustutil.WriteKustomization(fs, kust, overlaysDir); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing App-Proxy ingress manifests")

	return apu.PushWithMessage(ctx, r, "Created App-Proxy Ingress")
}

func updateCodefreshCM(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime, server string) error {
	var repofs fs.FS
	var marshalRuntime []byte
	var r apgit.Repository
	var err error

	r, repofs, err = opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get repo while updating codefresh-cm: %w", err)
	}

	codefreshCM := &v1.ConfigMap{}

	runtime, err := getRuntimeDataFromCodefreshCM(ctx, repofs, rt.Name, codefreshCM)
	if err != nil {
		return fmt.Errorf("failed to get runtime data while updating codefresh-cm: %w", err)
	}

	runtime.Spec.Cluster = server
	runtime.Spec.IngressClass = opts.IngressClass
	runtime.Spec.IngressController = opts.IngressController.Name()
	runtime.Spec.IngressHost = opts.IngressHost
	runtime.Spec.InternalIngressHost = opts.InternalIngressHost

	marshalRuntime, err = yaml.Marshal(runtime)
	if err != nil {
		return fmt.Errorf("failed to marshal runtime while updating codefresh-cm: %w", err)
	}

	codefreshCM.Data["runtime"] = string(marshalRuntime)
	err = repofs.WriteYamls(repofs.Join(apstore.Default.BootsrtrapDir, rt.Name+".yaml"), codefreshCM)
	if err != nil {
		return fmt.Errorf("failed to write file while updating codefresh-cm: %w", err)
	}

	err = apu.PushWithMessage(ctx, r, "Updating codefresh-cm")
	if err != nil {
		return fmt.Errorf("failed to push to git while updating codefresh-cm: %w", err)
	}

	return nil
}

func applySecretsToCluster(ctx context.Context, opts *RuntimeInstallOptions) error {
	runtimeTokenSecret, err := getRuntimeTokenSecret(opts.RuntimeName, opts.RuntimeToken, opts.RuntimeStoreIV)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	argoTokenSecret, err := getArgoCDTokenSecret(ctx, opts.kubeContext, opts.RuntimeName, opts.Insecure)
	if err != nil {
		return fmt.Errorf("failed to create argocd token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, aputil.JoinManifests(runtimeTokenSecret, argoTokenSecret)); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	return nil
}

func createEventsReporter(ctx context.Context, cloneOpts *apgit.CloneOptions, opts *RuntimeInstallOptions) error {
	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().EventsReporterName, opts.RuntimeName, "resources")
	u, err := url.Parse(cloneOpts.URL())
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}
	u.Path += "/" + resPath
	q := u.Query()
	q.Add("ref", cloneOpts.Revision())
	u.RawQuery = q.Encode()

	appDef := &runtime.AppDef{
		Name:       store.Get().EventsReporterName,
		Type:       application.AppTypeDirectory,
		URL:        u.String(),
		IsInternal: true,
	}
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", ""); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := createEventsReporterEventSource(repofs, resPath, opts.RuntimeName, opts.Insecure); err != nil {
		return err
	}

	eventsReporterTriggers := []string{"events"}
	if err := createSensor(repofs, store.Get().EventsReporterName, resPath, opts.RuntimeName, store.Get().EventsReporterName, eventsReporterTriggers, "data"); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Event Reporter manifests")

	return apu.PushWithMessage(ctx, r, "Created Codefresh Event Reporter")
}

func createReporter(ctx context.Context, cloneOpts *apgit.CloneOptions, opts *RuntimeInstallOptions, reporterCreateOpts reporterCreateOptions) error {
	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, reporterCreateOpts.reporterName, opts.RuntimeName, "resources")
	u, err := url.Parse(cloneOpts.URL())
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}
	u.Path += "/" + resPath
	q := u.Query()
	q.Add("ref", cloneOpts.Revision())
	u.RawQuery = q.Encode()

	appDef := &runtime.AppDef{
		Name:       reporterCreateOpts.reporterName,
		Type:       application.AppTypeDirectory,
		URL:        u.String(),
		IsInternal: reporterCreateOpts.IsInternal,
	}
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", ""); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := createReporterRBAC(repofs, resPath, opts.RuntimeName, reporterCreateOpts.saName, reporterCreateOpts.clusterScope); err != nil {
		return err
	}

	if err := createReporterEventSource(repofs, resPath, opts.RuntimeName, reporterCreateOpts, reporterCreateOpts.clusterScope); err != nil {
		return err
	}

	var triggerNames []string
	for _, gvr := range reporterCreateOpts.gvr {
		triggerNames = append(triggerNames, gvr.resourceName)
	}

	if err := createSensor(repofs, reporterCreateOpts.reporterName, resPath, opts.RuntimeName, reporterCreateOpts.reporterName, triggerNames, "data.object"); err != nil {
		return err
	}

	titleCase := cases.Title(language.AmericanEnglish)
	log.G(ctx).Info("Pushing Codefresh ", titleCase.String(reporterCreateOpts.reporterName), " manifests")

	pushMessage := "Created Codefresh" + titleCase.String(reporterCreateOpts.reporterName) + "Reporter"

	return apu.PushWithMessage(ctx, r, pushMessage)
}

func updateProject(repofs fs.FS, rt *runtime.Runtime) error {
	projPath := repofs.Join(apstore.Default.ProjectsDir, rt.Name+".yaml")
	project, appset, err := getProjectInfoFromFile(repofs, projPath)
	if err != nil {
		return err
	}

	if project.ObjectMeta.Labels == nil {
		project.ObjectMeta.Labels = make(map[string]string)
	}

	project.ObjectMeta.Labels[store.Get().LabelKeyCFType] = store.Get().CFRuntimeType

	return repofs.WriteYamls(projPath, project, appset)
}

func getRuntimeTokenSecret(namespace string, token string, iv string) ([]byte, error) {
	return yaml.Marshal(&v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().CFTokenSecret,
			Namespace: namespace,
			Labels: map[string]string{
				apstore.Default.LabelKeyAppManagedBy: apstore.Default.LabelValueManagedBy,
			},
		},
		Data: map[string][]byte{
			store.Get().CFTokenSecretKey:   []byte(token),
			store.Get().CFStoreIVSecretKey: []byte(iv),
		},
	})
}

func getArgoCDTokenSecret(ctx context.Context, kubeContext, namespace string, insecure bool) ([]byte, error) {
	token, err := cdutil.GenerateToken(ctx, "admin", kubeContext, namespace, insecure)
	if err != nil {
		return nil, err
	}

	return yaml.Marshal(&v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ArgoCDTokenSecret,
			Namespace: namespace,
			Labels: map[string]string{
				apstore.Default.LabelKeyAppPartOf: apstore.Default.ArgoCDNamespace,
			},
		},
		Data: map[string][]byte{
			store.Get().ArgoCDTokenKey: []byte(token),
		},
	})
}

func createReporterRBAC(repofs fs.FS, path, runtimeName, saName string, clusterScope bool) error {
	serviceAccount := &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: runtimeName,
		},
	}

	roleKind := "Role"
	roleMeta := metav1.ObjectMeta{
		Name:      saName,
		Namespace: runtimeName,
	}

	if clusterScope {
		roleKind = "ClusterRole"
		roleMeta = metav1.ObjectMeta{
			Name: saName,
		}
	}

	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       roleKind,
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: roleMeta,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}

	roleBindingKind := "RoleBinding"
	roleBindingMeta := metav1.ObjectMeta{
		Name:      saName,
		Namespace: runtimeName,
	}

	if clusterScope {
		roleBindingKind = "ClusterRoleBinding"
		roleBindingMeta = metav1.ObjectMeta{
			Name: saName,
		}
	}

	roleBinding := rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       roleBindingKind,
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: roleBindingMeta,
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: runtimeName,
				Name:      saName,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: roleKind,
			Name: saName,
		},
	}

	return repofs.WriteYamls(repofs.Join(path, "rbac.yaml"), serviceAccount, role, roleBinding)
}

func createEventsReporterEventSource(repofs fs.FS, path, namespace string, insecure bool) error {
	port := 443
	if insecure {
		port = 80
	}
	argoCDSvc := fmt.Sprintf("argocd-server.%s.svc:%d", namespace, port)

	eventSource := eventsutil.CreateEventSource(&eventsutil.CreateEventSourceOptions{
		Name:         store.Get().EventsReporterName,
		Namespace:    namespace,
		EventBusName: store.Get().EventBusName,
		Generic: map[string]eventsutil.CreateGenericEventSourceOptions{
			"events": {
				URL:             argoCDSvc,
				TokenSecretName: store.Get().ArgoCDTokenSecret,
				Insecure:        insecure,
			},
		},
	})
	return repofs.WriteYamls(repofs.Join(path, "event-source.yaml"), eventSource)
}

func createReporterEventSource(repofs fs.FS, path, namespace string, reporterCreateOpts reporterCreateOptions, clusterScope bool) error {
	var eventSource *aev1alpha1.EventSource
	var options *eventsutil.CreateEventSourceOptions

	var resourceNames []string
	for _, gvr := range reporterCreateOpts.gvr {
		resourceNames = append(resourceNames, gvr.resourceName)
	}

	options = &eventsutil.CreateEventSourceOptions{
		Name:               reporterCreateOpts.reporterName,
		Namespace:          namespace,
		ServiceAccountName: reporterCreateOpts.saName,
		EventBusName:       store.Get().EventBusName,
		Resource:           map[string]eventsutil.CreateResourceEventSourceOptions{},
	}

	resourceNamespace := namespace

	if clusterScope {
		resourceNamespace = ""
	}

	for i, name := range resourceNames {
		options.Resource[name] = eventsutil.CreateResourceEventSourceOptions{
			Group:     reporterCreateOpts.gvr[i].group,
			Version:   reporterCreateOpts.gvr[i].version,
			Resource:  reporterCreateOpts.gvr[i].resourceName,
			Namespace: resourceNamespace,
		}
	}

	eventSource = eventsutil.CreateEventSource(options)

	return repofs.WriteYamls(repofs.Join(path, "event-source.yaml"), eventSource)
}

func createSensor(repofs fs.FS, name, path, namespace, eventSourceName string, triggers []string, dataKey string) error {
	sensor := eventsutil.CreateSensor(&eventsutil.CreateSensorOptions{
		Name:            name,
		Namespace:       namespace,
		EventSourceName: eventSourceName,
		EventBusName:    store.Get().EventBusName,
		TriggerURL:      cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
		Triggers:        triggers,
		TriggerDestKey:  dataKey,
	})
	return repofs.WriteYamls(repofs.Join(path, "sensor.yaml"), sensor)
}

func ensureGitIntegrationOpts(opts *RuntimeInstallOptions) error {
	provider, err := parseGitProvider(string(opts.gitProvider.Type()))
	if err != nil {
		return err
	}

	opts.GitIntegrationCreationOpts.Provider = provider
	apiUrl := opts.gitProvider.ApiUrl()
	opts.GitIntegrationCreationOpts.APIURL = &apiUrl

	return nil
}

// display the user the old vs. the new configurations that will be changed upon recovery
// and asks for permission to proceed
func getInstallationFromRepoApproval(ctx context.Context, opts *RuntimeInstallOptions) error {
	server, err := util.KubeCurrentServer(opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("failed getting new cluster server: %w", err)
	}

	newConfigurations := map[string]string{
		"ClusterServer":     server,
		"IngressClass":      opts.IngressClass,
		"IngressController": opts.IngressController.Name(),
		"IngressHost":       opts.IngressHost,
	}
	_, repofs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get repo while getting user's approval: %w", err)
	}

	codefreshCM := &v1.ConfigMap{}
	runtime, err := getRuntimeDataFromCodefreshCM(ctx, repofs, opts.RuntimeName, codefreshCM)
	if err != nil {
		return err
	}

	previousConfigurations := map[string]string{
		"ClusterServer":     runtime.Spec.Cluster,
		"IngressClass":      runtime.Spec.IngressClass,
		"IngressController": runtime.Spec.IngressController,
		"IngressHost":       runtime.Spec.IngressHost,
	}

	printPreviousVsNewConfigsToUser(previousConfigurations, newConfigurations)

	if !store.Get().Silent {
		templates := &promptui.SelectTemplates{
			Selected: "{{ . | yellow }} ",
		}

		labelStr := fmt.Sprintf("%vDo you wish to proceed?%v", CYAN, COLOR_RESET)

		prompt := promptui.Select{
			Label:     labelStr,
			Items:     []string{"Yes", "No"},
			Templates: templates,
		}

		_, result, err := prompt.Run()
		if err != nil {
			return err
		}

		if result == "No" {
			return fmt.Errorf("installation from existing repo was cancelled")
		}
	}

	return nil
}

func getRuntimeDataFromCodefreshCM(_ context.Context, repofs fs.FS, runtimeName string, codefreshCM *v1.ConfigMap) (*runtime.Runtime, error) {
	err := repofs.ReadYamls(repofs.Join(apstore.Default.BootsrtrapDir, runtimeName+".yaml"), codefreshCM)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %w", runtimeName+".yaml", err)
	}

	data := codefreshCM.Data["runtime"]
	runtime := &runtime.Runtime{}
	err = yaml.Unmarshal([]byte(data), runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime: %w", err)
	}

	return runtime, nil
}

func postInstallationHandler(ctx context.Context, opts *RuntimeInstallOptions, err error, disableRollback *bool) {
	if err != nil && !*disableRollback {
		summaryArr = append(summaryArr, summaryLog{"----------Uninstalling runtime----------", Info})
		log.G(ctx).Warnf("installation failed due to error : %s, performing installation rollback", err.Error())

		err := RunRuntimeUninstall(ctx, &RuntimeUninstallOptions{
			RuntimeName: opts.RuntimeName,
			Timeout:     store.Get().WaitTimeout,
			CloneOpts:   opts.InsCloneOpts,
			KubeFactory: opts.KubeFactory,
			SkipChecks:  true,
			Force:       true,
			FastExit:    false,
		})
		handleCliStep(reporter.UninstallPhaseFinish, "Uninstall phase finished after rollback", err, false, true)
		if err != nil {
			log.G(ctx).Errorf("installation rollback failed: %s", err.Error())
		}
	}

	printSummaryToUser()
}

func printPreviousVsNewConfigsToUser(previousConfigurations map[string]string, newConfigurations map[string]string) {
	fmt.Printf("%vYou are about to recover a runtime from an existing repo. some configuration will be changed as follows:\n%v", CYAN, COLOR_RESET)
	fmt.Printf("%vCluster server:%v     %s %v--> %s%v\n", BOLD, BOLD_RESET, previousConfigurations["ClusterServer"], GREEN, newConfigurations["ClusterServer"], COLOR_RESET)
	fmt.Printf("%vIngress class:%v      %s %v--> %s%v\n", BOLD, BOLD_RESET, previousConfigurations["IngressClass"], GREEN, newConfigurations["IngressClass"], COLOR_RESET)
	fmt.Printf("%vIngress controller:%v %s %v--> %s%v\n", BOLD, BOLD_RESET, previousConfigurations["IngressController"], GREEN, newConfigurations["IngressController"], COLOR_RESET)
	fmt.Printf("%vIngress host:%v       %s %v--> %s%v\n", BOLD, BOLD_RESET, previousConfigurations["IngressHost"], GREEN, newConfigurations["IngressHost"], COLOR_RESET)
}

func getVersionIfExists(versionStr string) (*semver.Version, error) {
	if versionStr != "" {
		log.G().Infof("vesionStr: %s", versionStr)
		return semver.NewVersion(versionStr)
	}

	return nil, nil
}

func initializeGitSourceCloneOpts(opts *RuntimeInstallOptions) {
	opts.GsCloneOpts.Provider = opts.InsCloneOpts.Provider
	opts.GsCloneOpts.Auth = opts.InsCloneOpts.Auth
	opts.GsCloneOpts.Progress = opts.InsCloneOpts.Progress
	host, orgRepo, _, _, _, suffix, _ := aputil.ParseGitUrl(opts.InsCloneOpts.Repo)
	opts.GsCloneOpts.Repo = host + orgRepo + "_git-source" + suffix + "/resources" + "_" + opts.RuntimeName
}
