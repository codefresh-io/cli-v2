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
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	appset "github.com/argoproj/applicationset/api/v1alpha1"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	argocdv1alpha1cs "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
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
		IngressHost                    string
		IngressClass                   string
		IngressController              ingressutil.IngressController
		Insecure                       bool
		InstallDemoResources           bool
		SkipClusterChecks              bool
		DisableRollback                bool
		DisableTelemetry               bool
		Version                        *semver.Version
		GsCloneOpts                    *git.CloneOptions
		InsCloneOpts                   *git.CloneOptions
		GitIntegrationCreationOpts     *apmodel.AddGitIntegrationArgs
		GitIntegrationRegistrationOpts *apmodel.RegisterToGitIntegrationArgs
		KubeFactory                    kube.Factory
		CommonConfig                   *runtime.CommonConfig
		NamespaceLabels                map[string]string
		versionStr                     string
		kubeContext                    string
		kubeconfig                     string
	}

	RuntimeUninstallOptions struct {
		RuntimeName      string
		Timeout          time.Duration
		CloneOpts        *git.CloneOptions
		KubeFactory      kube.Factory
		SkipChecks       bool
		Force            bool
		FastExit         bool
		DisableTelemetry bool
		kubeContext      string
	}

	RuntimeUpgradeOptions struct {
		RuntimeName      string
		Version          *semver.Version
		CloneOpts        *git.CloneOptions
		CommonConfig     *runtime.CommonConfig
		DisableTelemetry bool
	}

	gvr struct {
		resourceName string
		group        string
		version      string
	}

	reporterCreateOptions struct {
		reporterName string
		gvr          []gvr
		saName       string
		IsInternal   bool
	}

	summaryLogLevels string
	summaryLog       struct {
		message string
		level   summaryLogLevels
	}
)

const (
	Success summaryLogLevels = "Success"
	Failed  summaryLogLevels = "Failed"
	Info    summaryLogLevels = "Info"
)

var summaryArr []summaryLog

func NewRuntimeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "runtime",
		Short:             "Manage Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewRuntimeInstallCommand())
	cmd.AddCommand(NewRuntimeListCommand())
	cmd.AddCommand(NewRuntimeUninstallCommand())
	cmd.AddCommand(NewRuntimeUpgradeCommand())

	cmd.PersistentFlags().BoolVar(&store.Get().Silent, "silent", false, "Disables the command wizard")

	return cmd
}

func NewRuntimeInstallCommand() *cobra.Command {
	var (
		gitIntegrationCreationOpts = apmodel.AddGitIntegrationArgs{
			SharingPolicy: apmodel.SharingPolicyAllUsersInAccount,
		}
		installationOpts = RuntimeInstallOptions{
			GitIntegrationCreationOpts:     &gitIntegrationCreationOpts,
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

			err := runtimeInstallCommandPreRunHandler(cmd, &installationOpts)
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

			if err := getApprovalFromUser(cmd.Context(), finalParameters, "runtime install"); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := RunRuntimeInstall(cmd.Context(), &installationOpts)
			handleCliStep(reporter.InstallPhaseFinish, "Runtime installation phase finished", err, false, false)
			return err
		},
	}

	cmd.Flags().StringVar(&installationOpts.IngressHost, "ingress-host", "", "The ingress host")
	cmd.Flags().StringVar(&installationOpts.IngressClass, "ingress-class", "", "The ingress class name")
	cmd.Flags().StringVar(&installationOpts.GitIntegrationRegistrationOpts.Token, "personal-git-token", "", "The Personal git token for your user")
	cmd.Flags().StringVar(&installationOpts.versionStr, "version", "", "The runtime version to install (default: latest)")
	cmd.Flags().BoolVar(&installationOpts.InstallDemoResources, "demo-resources", true, "Installs demo resources (default: true)")
	cmd.Flags().BoolVar(&installationOpts.SkipClusterChecks, "skip-cluster-checks", false, "Skips the cluster's checks")
	cmd.Flags().BoolVar(&installationOpts.DisableRollback, "disable-rollback", false, "If true, will not perform installation rollback after a failed installation")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be ready")
	cmd.Flags().StringVar(&gitIntegrationCreationOpts.APIURL, "provider-api-url", "", "Git provider API url")
	cmd.Flags().BoolVar(&store.Get().SkipIngress, "skip-ingress", false, "Skips the creation of ingress resources")
	cmd.Flags().BoolVar(&store.Get().BypassIngressClassCheck, "bypass-ingress-class-check", false, "Disables the ingress class check during pre-installation")
	cmd.Flags().BoolVar(&installationOpts.DisableTelemetry, "disable-telemetry", false, "If true, will disable the analytics reporting for the installation process")
	cmd.Flags().BoolVar(&store.Get().SetDefaultResources, "set-default-resources", false, "If true, will set default requests and limits on all of the runtime components")
	cmd.Flags().StringToStringVar(&installationOpts.NamespaceLabels, "namespace-labels", nil, "Optional labels that will be set on the namespace resource. (e.g. \"key1=value1,key2=value2\"")

	installationOpts.InsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
		CloneForWrite:    true,
	})

	installationOpts.GsCloneOpts = &git.CloneOptions{
		FS:               fs.Create(memfs.New()),
		CreateIfNotExist: true,
	}

	installationOpts.KubeFactory = kube.AddFlags(cmd.Flags())
	installationOpts.kubeconfig = cmd.Flag("kubeconfig").Value.String()

	util.Die(cmd.Flags().MarkHidden("bypass-ingress-class-check"))

	return cmd
}

func runtimeInstallCommandPreRunHandler(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	var err error
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

	err = ensureIngressClass(cmd.Context(), opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureIngressClass, "Getting ingress class", err, true, false)
	if err != nil {
		return err
	}

	err = ensureIngressHost(cmd, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureIngressHost, "Getting ingressHost", err, true, false)
	if err != nil {
		return err
	}

	err = ensureRepo(cmd, opts.RuntimeName, opts.InsCloneOpts, false)
	handleCliStep(reporter.InstallStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	inferProviderFromRepo(opts.InsCloneOpts)

	err = ensureGitToken(cmd, opts.InsCloneOpts, true)
	handleCliStep(reporter.InstallStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	err = ensureGitPAT(cmd, opts)
	handleCliStep(reporter.InstallStepPreCheckEnsureGitPAT, "Getting git personal access token", err, true, false)
	if err != nil {
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

	opts.Insecure = true // installs argo-cd in insecure mode, we need this so that the eventsource can talk to the argocd-server with http
	opts.CommonConfig = &runtime.CommonConfig{CodefreshBaseURL: cfConfig.GetCurrentContext().URL}

	return nil
}

func runtimeUninstallCommandPreRunHandler(cmd *cobra.Command, args []string, opts *RuntimeUninstallOptions) error {
	var err error
	handleCliStep(reporter.UninstallPhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.kubeContext, err = getKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
	handleCliStep(reporter.UninstallStepPreCheckGetKubeContext, "Getting kube context name", err, true, false)
	if err != nil {
		return err
	}

	opts.RuntimeName, err = ensureRuntimeName(cmd.Context(), args)
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeName, "Ensuring runtime name", err, true, false)
	if err != nil {
		return err
	}

	err = ensureRepo(cmd, opts.RuntimeName, opts.CloneOpts, true)
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	err = ensureGitToken(cmd, opts.CloneOpts, false)
	handleCliStep(reporter.UninstallStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	return nil
}

func runtimeUpgradeCommandPreRunHandler(cmd *cobra.Command, args []string, opts *RuntimeUpgradeOptions) error {
	var err error

	handleCliStep(reporter.UpgradePhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.RuntimeName, err = ensureRuntimeName(cmd.Context(), args)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureRuntimeName, "Ensuring runtime name", err, true, false)
	if err != nil {
		return err
	}

	err = ensureRepo(cmd, opts.RuntimeName, opts.CloneOpts, true)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	err = ensureGitToken(cmd, opts.CloneOpts, false)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	return nil
}

func ensureIngressHost(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	if opts.IngressHost == "" { // ingress host not provided by flag
		if err := setIngressHost(cmd.Context(), opts); err != nil {
			return err
		}
	}

	parsed, err := url.Parse(opts.IngressHost)
	if err != nil {
		return err
	}

	isIP := util.IsIP(parsed.Host)
	if !isIP {
		opts.HostName, _, err = net.SplitHostPort(parsed.Host)
		if err != nil {
			if err.Error() == fmt.Sprintf("address %s: missing port in address", parsed.Host) {
				opts.HostName = parsed.Host
			} else {
				return err
			}
		}
	}

	log.G(cmd.Context()).Infof("Using ingress host: %s", opts.IngressHost)

	log.G(cmd.Context()).Info("Validating ingress host")

	certValid, err := checkIngressHostCertificate(opts.IngressHost)
	if err != nil {
		log.G(cmd.Context()).Fatalf("failed to check ingress host: %v", err)
	}

	if !certValid {
		if err = askUserIfToProceedWithInsecure(cmd.Context()); err != nil {
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

func RunRuntimeInstall(ctx context.Context, opts *RuntimeInstallOptions) error {
	err := preInstallationChecks(ctx, opts)
	handleCliStep(reporter.InstallPhaseRunPreCheckFinish, "Pre run installation checks", err, true, true)
	if err != nil {
		return fmt.Errorf("pre installation checks failed: %w", err)
	}

	handleCliStep(reporter.InstallPhaseStart, "Runtime installation phase started", nil, false, true)

	rt, server, err := runtimeInstallPreparations(opts)
	if err != nil {
		return err
	}

	runtimeVersion := rt.Spec.Version.String()

	componentNames := getComponents(rt, opts)

	disableRollback := opts.DisableRollback

	defer func() {
		// will rollback if err is not nil and it is safe to do so
		postInstallationHandler(ctx, opts, err, &disableRollback)
	}()

	ingressControllerName := opts.IngressController.Name()

	token, iv, err := createRuntimeOnPlatform(ctx, &model.RuntimeInstallationArgs{
		RuntimeName:       opts.RuntimeName,
		Cluster:           server,
		RuntimeVersion:    runtimeVersion,
		IngressHost:       &opts.IngressHost,
		IngressClass:      &opts.IngressClass,
		IngressController: &ingressControllerName,
		ComponentNames:    componentNames,
		Repo:              &opts.InsCloneOpts.Repo,
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
	rt.Spec.IngressController = string(opts.IngressController.Name())
	rt.Spec.Repo = opts.InsCloneOpts.Repo

	log.G(ctx).WithField("version", rt.Spec.Version).Infof("Installing runtime \"%s\"", opts.RuntimeName)
	repoExists, err := apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier:    rt.Spec.FullSpecifier(),
		Namespace:       opts.RuntimeName,
		KubeFactory:     opts.KubeFactory,
		CloneOptions:    opts.InsCloneOpts,
		Insecure:        opts.Insecure,
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

	if !repoExists {
		err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
			CloneOpts:   opts.InsCloneOpts,
			ProjectName: opts.RuntimeName,
			Labels: map[string]string{
				store.Get().LabelKeyCFType:     fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFType)),
				store.Get().LabelKeyCFInternal: fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFInternal)),
			},
		})
	}
	handleCliStep(reporter.InstallStepCreateProject, "Creating Project", err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create project: %w", err))
	}

	// persists codefresh-cm, this must be created before events-reporter eventsource
	// otherwise it will not start and no events will get to the platform.
	if !repoExists {
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

	if !repoExists {
		err = createRuntimeComponents(ctx, opts, rt)
		if err != nil {
			return err
		}
	}

	if !repoExists {
		err = createGitSources(ctx, opts)
		if err != nil {
			return err
		}
	}

	timeoutErr := intervalCheckIsRuntimePersisted(ctx, opts.RuntimeName)
	handleCliStep(reporter.InstallStepCompleteRuntimeInstallation, "Wait for runtime sync", timeoutErr, false, true)

	// if we got to this point the runtime was installed successfully
	// thus we shall not perform a rollback after this point.
	disableRollback = true

	if store.Get().SkipIngress {
		handleCliStep(reporter.InstallStepCreateDefaultGitIntegration, "-skipped-", err, false, true)
		handleCliStep(reporter.InstallStepRegisterToDefaultGitIntegration, "-skipped-", err, false, true)

		skipIngressInfoMsg := util.Doc(fmt.Sprintf(`
To complete the installation: 
1. Configure your cluster's routing service with path to '/%s' and \"%s\"
2. Create and register Git integration using the commands:

<BIN> integration git add default --runtime %s --api-url %s

<BIN> integration git register default --runtime %s --token <AUTHENTICATION_TOKEN>
`,
			store.Get().AppProxyIngressPath,
			util.GenerateIngressEventSourcePath(opts.RuntimeName),
			opts.RuntimeName,
			opts.GitIntegrationCreationOpts.APIURL,
			opts.RuntimeName))
		summaryArr = append(summaryArr, summaryLog{skipIngressInfoMsg, Info})
	} else {
		gitIntegrationErr := createGitIntegration(ctx, opts)
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

func runtimeInstallPreparations(opts *RuntimeInstallOptions) (*runtime.Runtime, string, error) {
	rt, err := runtime.Download(opts.Version, opts.RuntimeName)
	handleCliStep(reporter.InstallStepDownloadRuntimeDefinition, "Downloading runtime definition", err, false, true)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download runtime definition: %w", err)
	}

	server, err := util.KubeCurrentServer(opts.kubeconfig)
	handleCliStep(reporter.InstallStepGetServerAddress, "Getting current server address", err, false, true)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get current server address: %w", err)
	}

	return rt, server, nil
}

func createRuntimeComponents(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	var err error
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

	handleCliStep(reporter.InstallStepCreateComponents, "Creating components", err, false, true)
	if err != nil {
		return err
	}

	if opts.IngressController.Name() == string(ingressutil.IngressControllerNginxEnterprise) {
		err := createMasterIngressResource(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to create master ingress resource: %w", err)
		}
	}

	err = installComponents(ctx, opts, rt)
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

	ingress := ingressutil.CreateIngress(&ingressutil.CreateIngressOptions{
		Name:             opts.RuntimeName + store.Get().MasterIngressName,
		Namespace:        opts.RuntimeName,
		IngressClassName: opts.IngressClass,
		Host:             opts.HostName,
		Annotations: map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
		},
	})

	if err = fs.WriteYamls(fs.Join(store.Get().InClusterPath, "master-ingress.yaml"), ingress); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Master Ingress Manifest")

	return apu.PushWithMessage(ctx, r, "Created master ingress resource")
}

func createGitSources(ctx context.Context, opts *RuntimeInstallOptions) error {
	gitSrcMessage := fmt.Sprintf("Creating git source \"%s\"", store.Get().GitSourceName)
	err := RunGitSourceCreate(ctx, &GitSourceCreateOptions{
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
	handleCliStep(reporter.InstallStepCreateGitsource, gitSrcMessage, err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\": %w", store.Get().GitSourceName, err))
	}

	mpCloneOpts := &git.CloneOptions{
		Repo: store.Get().MarketplaceRepo,
		FS:   fs.Create(memfs.New()),
	}
	mpCloneOpts.Parse()

	createGitSrcMessgae := fmt.Sprintf("Creating %s", store.Get().MarketplaceGitSourceName)

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
	handleCliStep(reporter.InstallStepCreateMarketplaceGitsource, createGitSrcMessgae, err, false, true)
	if err != nil {
		return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\": %w", store.Get().MarketplaceGitSourceName, err))
	}

	return nil
}

func createGitIntegration(ctx context.Context, opts *RuntimeInstallOptions) error {
	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client: %w", err)
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

func removeGitIntegrations(ctx context.Context, opts *RuntimeUninstallOptions) error {
	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client: %w", err)
	}

	integrations, err := appProxyClient.GitIntegrations().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to get list of git integrations: %w", err)
	}

	for _, intg := range integrations {
		if err = RunGitIntegrationRemoveCommand(ctx, appProxyClient, intg.Name); err != nil {
			command := util.Doc(fmt.Sprintf("\t<BIN> integration git remove %s", intg.Name))

			return fmt.Errorf(`%w. You can try to remove it manually by running: %s`, err, command)
		}
	}

	return nil
}

func addDefaultGitIntegration(ctx context.Context, appProxyClient codefresh.AppProxyAPI, runtime string, opts *apmodel.AddGitIntegrationArgs) error {
	if err := RunGitIntegrationAddCommand(ctx, appProxyClient, opts); err != nil {
		command := util.Doc(fmt.Sprintf(
			"\t<BIN> integration git add default --runtime %s --provider %s --api-url %s",
			runtime,
			strings.ToLower(opts.Provider.String()),
			opts.APIURL,
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
		saName:     store.Get().RolloutReporterServiceAccount,
		IsInternal: true,
	}); err != nil {
		return fmt.Errorf("failed to create rollout-reporter: %w", err)
	}

	return nil
}

func preInstallationChecks(ctx context.Context, opts *RuntimeInstallOptions) error {
	log.G(ctx).Debug("running pre-installation checks...")

	handleCliStep(reporter.InstallPhaseRunPreCheckStart, "Running pre run installation checks", nil, true, false)

	rt, err := runtime.Download(opts.Version, opts.RuntimeName)
	handleCliStep(reporter.InstallStepRunPreCheckDownloadRuntimeDefinition, "Downloading runtime definition", err, true, true)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	if rt.Spec.DefVersion.GreaterThan(store.Get().MaxDefVersion) {
		err = fmt.Errorf("your cli version is out of date. please upgrade to the latest version before installing")
	}
	handleCliStep(reporter.InstallStepRunPreCheckEnsureCliVersion, "Checking CLI version", err, true, false)
	if err != nil {
		return util.DecorateErrorWithDocsLink(err, store.Get().DownloadCliLink)
	}

	err = checkRuntimeCollisions(ctx, opts.KubeFactory, opts.RuntimeName)
	handleCliStep(reporter.InstallStepRunPreCheckRuntimeCollision, "Checking for runtime collisions", err, true, false)
	if err != nil {
		return fmt.Errorf("runtime collision check failed: %w", err)
	}

	if !opts.SkipClusterChecks {
		err = kubeutil.EnsureClusterRequirements(ctx, opts.KubeFactory, opts.RuntimeName, cfConfig.GetCurrentContext().URL)
	}
	handleCliStep(reporter.InstallStepRunPreCheckValidateClusterRequirements, "Ensuring cluster requirements", err, true, false)
	if err != nil {
		return fmt.Errorf("validation of minimum cluster requirements failed: %w", err)
	}

	return nil
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

func getComponentChecklistState(c model.Component) (checklist.ListItemState, checklist.ListItemInfo) {
	state := checklist.Waiting
	name := strings.TrimPrefix(c.Metadata.Name, fmt.Sprintf("%s-", c.Metadata.Runtime))
	version := "N/A"
	syncStatus := "N/A"
	healthStatus := "N/A"
	errs := ""

	if c.Version != "" {
		version = c.Version
	}

	if c.Self != nil && c.Self.Status != nil {
		syncStatus = string(c.Self.Status.SyncStatus)

		if c.Self.Status.HealthStatus != nil {
			healthStatus = string(*c.Self.Status.HealthStatus)
		}

		if len(c.Self.Errors) > 0 {
			// use the first sync error due to lack of space
			for _, err := range c.Self.Errors {
				se, ok := err.(model.SyncError)
				if ok && se.Level == model.ErrorLevelsError {
					errs = se.Message
					state = checklist.Error
				}
			}
		}
	}

	if healthStatus == string(model.HealthStatusHealthy) && syncStatus == string(model.SyncStatusSynced) {
		state = checklist.Ready
	}

	return state, []string{name, healthStatus, syncStatus, version, errs}
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

func NewRuntimeListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		Short:   "List all Codefresh runtimes",
		Example: util.Doc("<BIN> runtime list"),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			return RunRuntimeList(ctx)
		},
	}

	return cmd
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
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tVERSION\tSYNC_STATUS\tHEALTH_STATUS\tHEALTH_MESSAGE\tINSTALLATION_STATUS\tINGRESS_HOST")
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
		ingressClass := "N/A"

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

		if rt.IngressClass != nil {
			ingressClass = *rt.IngressClass
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			version,
			syncStatus,
			healthStatus,
			healthMessage,
			installationStatus,
			ingressHost,
			ingressClass,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func NewRuntimeUninstallCommand() *cobra.Command {
	var (
		opts            RuntimeUninstallOptions
		finalParameters map[string]string
	)

	cmd := &cobra.Command{
		Use:   "uninstall [RUNTIME_NAME]",
		Short: "Uninstall a Codefresh runtime",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export GIT_TOKEN=<token>

# or with the flag:

		--git-token <token>

# Deletes a runtime

	<BIN> runtime uninstall runtime-name --repo gitops_repo
`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			createAnalyticsReporter(ctx, reporter.UninstallFlow, opts.DisableTelemetry)

			err := runtimeUninstallCommandPreRunHandler(cmd, args, &opts)
			handleCliStep(reporter.UninstallPhasePreCheckFinish, "Finished pre run checks", err, true, false)
			if err != nil {
				if errors.Is(err, promptui.ErrInterrupt) {
					return fmt.Errorf("uninstallation canceled by user")
				}

				return fmt.Errorf("pre run error: %w", err)
			}

			finalParameters = map[string]string{
				"Codefresh context": cfConfig.CurrentContext,
				"Kube context":      opts.kubeContext,
				"Runtime name":      opts.RuntimeName,
				"Repository URL":    opts.CloneOpts.Repo,
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime uninstall")
			if err != nil {
				return err
			}

			opts.Timeout = store.Get().WaitTimeout
			opts.CloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := RunRuntimeUninstall(cmd.Context(), &opts)
			handleCliStep(reporter.UninstallPhaseFinish, "Uninstall phase finished", err, false, true)
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.SkipChecks, "skip-checks", false, "If true, will not verify that runtime exists before uninstalling")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be deleted")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "If true, will guarantee the runtime is removed from the platform, even in case of errors while cleaning the repo and the cluster")
	cmd.Flags().BoolVar(&opts.FastExit, "fast-exit", false, "If true, will not wait for deletion of cluster resources. This means that full resource deletion will not be verified")
	cmd.Flags().BoolVar(&opts.DisableTelemetry, "disable-telemetry", false, "If true, will disable the analytics reporting for the uninstall process")

	opts.CloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{CloneForWrite: true})
	opts.KubeFactory = kube.AddFlags(cmd.Flags())

	return cmd
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

	subCtx, cancel := context.WithCancel(ctx)
	go func() {
		if err := printApplicationsState(subCtx, opts.RuntimeName, opts.KubeFactory); err != nil {
			log.G(ctx).WithError(err).Debug("failed to print uninstallation progress")
		}
	}()

	err = apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
		Namespace:    opts.RuntimeName,
		Timeout:      opts.Timeout,
		CloneOptions: opts.CloneOpts,
		KubeFactory:  opts.KubeFactory,
		Force:        opts.Force,
		FastExit:     opts.FastExit,
	})
	cancel() // to tell the progress to stop displaying even if it's not finished
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepUninstallRepo, "Uninstalling repo", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	err = deleteRuntimeFromPlatform(ctx, opts)
	handleCliStep(reporter.UninstallStepDeleteRuntimeFromPlatform, "Deleting runtime from platform", err, false, true)
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

func printApplicationsState(ctx context.Context, runtime string, f kube.Factory) error {
	apps := map[string]*argocdv1alpha1.Application{}
	lock := sync.Mutex{}

	rc, err := f.ToRESTConfig()
	if err != nil {
		return err
	}

	cs, err := argocdv1alpha1cs.NewForConfig(rc)
	if err != nil {
		return err
	}

	appIf := cs.ArgoprojV1alpha1().Applications(runtime)
	componentsLabelSelector := fmt.Sprintf("%s=%s", store.Get().LabelKeyCFType, store.Get().CFComponentType)

	curApps, err := appIf.List(ctx, metav1.ListOptions{LabelSelector: componentsLabelSelector})
	if err != nil {
		return err
	}

	if len(curApps.Items) == 0 {
		// all apps already deleted nothing to wait for
		return nil
	}

	for i, a := range curApps.Items {
		apps[a.Name] = &curApps.Items[i]
	}

	// refresh components state
	go func() {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			curApps, err := appIf.List(ctx, metav1.ListOptions{LabelSelector: componentsLabelSelector})
			if err != nil {
				log.G(ctx).WithError(err).Debug("failed to refresh components state")
				continue
			}

			newApps := make(map[string]*argocdv1alpha1.Application, len(curApps.Items))
			for i, a := range curApps.Items {
				newApps[a.Name] = &curApps.Items[i]
			}

			lock.Lock()
			// update existing
			for i, a := range curApps.Items {
				apps[a.Name] = &curApps.Items[i]
			}

			// clear deleted apps
			for name := range apps {
				if _, ok := newApps[name]; !ok {
					delete(apps, name)
				}
			}
			lock.Unlock()
		}
	}()

	checkers := make([]checklist.Checker, len(curApps.Items))
	for i, a := range curApps.Items {
		name := a.Name
		checkers[i] = func(ctx context.Context) (checklist.ListItemState, checklist.ListItemInfo) {
			lock.Lock()
			defer lock.Unlock()
			return getApplicationChecklistState(name, apps[name], runtime)
		}
	}

	cl := checklist.NewCheckList(
		os.Stdout,
		checklist.ListItemInfo{"COMPONENT", "STATUS"},
		checkers,
		&checklist.CheckListOptions{
			WaitAllReady: true,
		},
	)

	if err := cl.Start(ctx); err != nil && ctx.Err() == nil {
		return err
	}

	return nil
}

func getApplicationChecklistState(name string, a *argocdv1alpha1.Application, runtime string) (checklist.ListItemState, checklist.ListItemInfo) {
	state := checklist.Waiting
	name = strings.TrimPrefix(name, fmt.Sprintf("%s-", runtime))
	status := "N/A"

	if a == nil {
		status = "Deleted"
		state = checklist.Ready
	} else if string(a.Status.Health.Status) != "" {
		status = string(a.Status.Health.Status)
	}

	return state, []string{name, status}
}

func deleteRuntimeFromPlatform(ctx context.Context, opts *RuntimeUninstallOptions) error {
	log.G(ctx).Infof("Deleting runtime \"%s\" from the platform", opts.RuntimeName)
	_, err := cfConfig.NewClient().V2().Runtime().Delete(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Successfully deleted runtime \"%s\" from the platform", opts.RuntimeName)
	return nil
}

func NewRuntimeUpgradeCommand() *cobra.Command {
	var (
		versionStr      string
		finalParameters map[string]string
		opts            RuntimeUpgradeOptions
	)

	cmd := &cobra.Command{
		Use:   "upgrade [RUNTIME_NAME]",
		Short: "Upgrade a Codefresh runtime",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export GIT_TOKEN=<token>

# or with the flag:

		--git-token <token>

# Upgrade a runtime to version v0.0.30

	<BIN> runtime upgrade runtime-name --version 0.0.30 --repo gitops_repo
`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			createAnalyticsReporter(ctx, reporter.UpgradeFlow, opts.DisableTelemetry)

			err := runtimeUpgradeCommandPreRunHandler(cmd, args, &opts)
			handleCliStep(reporter.UpgradePhasePreCheckFinish, "Finished pre run checks", err, true, false)
			if err != nil {
				if errors.Is(err, promptui.ErrInterrupt) {
					return fmt.Errorf("upgrade canceled by user")
				}
				return fmt.Errorf("pre run error: %w", err)
			}

			finalParameters = map[string]string{
				"Codefresh context": cfConfig.CurrentContext,
				"Runtime name":      opts.RuntimeName,
				"Repository URL":    opts.CloneOpts.Repo,
			}

			if versionStr != "" {
				finalParameters["Version"] = versionStr
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime upgrade")
			if err != nil {
				return err
			}

			opts.CloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			ctx := cmd.Context()

			if versionStr != "" {
				opts.Version, err = semver.NewVersion(versionStr)
				if err != nil {
					return err
				}
			}

			opts.CommonConfig = &runtime.CommonConfig{
				CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
			}

			err = RunRuntimeUpgrade(ctx, &opts)
			handleCliStep(reporter.UpgradePhaseFinish, "Runtime upgrade phase finished", err, false, false)
			return err
		},
	}

	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to upgrade to, defaults to latest")
	cmd.Flags().BoolVar(&opts.DisableTelemetry, "disable-telemetry", false, "If true, will disable analytics reporting for the upgrade process")
	cmd.Flags().BoolVar(&store.Get().SetDefaultResources, "set-default-resources", false, "If true, will set default requests and limits on all of the runtime components")
	opts.CloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{CloneForWrite: true})

	return cmd
}

func RunRuntimeUpgrade(ctx context.Context, opts *RuntimeUpgradeOptions) error {
	handleCliStep(reporter.UpgradePhaseStart, "Runtime upgrade phase started", nil, false, true)

	log.G(ctx).Info("Downloading runtime definition")
	newRt, err := runtime.Download(opts.Version, opts.RuntimeName)
	handleCliStep(reporter.UpgradeStepDownloadRuntimeDefinition, "Downloading runtime definition", err, true, false)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	if newRt.Spec.DefVersion.GreaterThan(store.Get().MaxDefVersion) {
		err = fmt.Errorf("please upgrade your cli version before upgrading to %s", newRt.Spec.Version)
	}
	handleCliStep(reporter.UpgradeStepRunPreCheckEnsureCliVersion, "Checking CLI version", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Info("Cloning installation repository")
	r, fs, err := opts.CloneOpts.GetRepo(ctx)
	handleCliStep(reporter.UpgradeStepGetRepo, "Getting repository", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Info("Loading current runtime definition")
	curRt, err := runtime.Load(fs, fs.Join(apstore.Default.BootsrtrapDir, opts.RuntimeName+".yaml"))
	handleCliStep(reporter.UpgradeStepLoadRuntimeDefinition, "Loading runtime definition", err, true, false)
	if err != nil {
		return fmt.Errorf("failed to load current runtime definition: %w", err)
	}

	if !newRt.Spec.Version.GreaterThan(curRt.Spec.Version) {
		err = fmt.Errorf("current runtime version (%s) is greater than or equal to the specified version (%s)", curRt.Spec.Version, newRt.Spec.Version)
	}
	handleCliStep(reporter.UpgradeStepLoadRuntimeDefinition, "Comparing runtime versions", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Upgrading runtime \"%s\" to version: v%s", opts.RuntimeName, newRt.Spec.Version)
	newComponents, err := curRt.Upgrade(fs, newRt, opts.CommonConfig)
	handleCliStep(reporter.UpgradeStepUpgradeRuntime, "Upgrading runtime", err, false, false)
	if err != nil {
		return fmt.Errorf("failed to upgrade runtime: %w", err)
	}

	log.G(ctx).Info("Pushing new runtime definition")
	err = apu.PushWithMessage(ctx, r, fmt.Sprintf("Upgraded to %s", newRt.Spec.Version))
	handleCliStep(reporter.UpgradeStepPushRuntimeDefinition, "Pushing new runtime definition", err, false, false)
	if err != nil {
		return err
	}

	for _, component := range newComponents {
		log.G(ctx).Infof("Installing new component \"%s\"", component.Name)
		component.IsInternal = true
		err = component.CreateApp(ctx, nil, opts.CloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", "")
		if err != nil {
			err = fmt.Errorf("failed to create \"%s\" application: %w", component.Name, err)
			break
		}
	}

	handleCliStep(reporter.UpgradeStepInstallNewComponents, "Install new components", err, false, false)

	log.G(ctx).Infof("Runtime upgraded to version: v%s", newRt.Spec.Version)

	return nil
}

func persistRuntime(ctx context.Context, cloneOpts *git.CloneOptions, rt *runtime.Runtime, rtConf *runtime.CommonConfig) error {
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

	if !store.Get().SkipIngress {
		ingressOptions := ingressutil.CreateIngressOptions{
			Name:             rt.Name + store.Get().AppProxyIngressName,
			Namespace:        rt.Namespace,
			IngressClassName: opts.IngressClass,
			Host:             opts.HostName,
			Paths: []ingressutil.IngressPath{
				{
					Path:        store.Get().AppProxyIngressPath,
					PathType:    netv1.PathTypePrefix,
					ServiceName: store.Get().AppProxyServiceName,
					ServicePort: store.Get().AppProxyServicePort,
				},
			},
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
	var r git.Repository
	var err error

	r, repofs, err = opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get repo while updating codefresh-cm: %w", err)
	}

	codefreshCM := &v1.ConfigMap{}
	err = repofs.ReadYamls(repofs.Join(apstore.Default.BootsrtrapDir, rt.Name+".yaml"), codefreshCM)
	if err != nil {
		return fmt.Errorf("failed to read file while updating codefresh-cm: %w", err)
	}

	data := codefreshCM.Data["runtime"]
	runtime := &runtime.Runtime{}
	err = yaml.Unmarshal([]byte(data), runtime)
	if err != nil {
		return fmt.Errorf("failed to unmarshal runtime while updating codefresh-cm: %w", err)
	}

	runtime.Spec.Cluster = server
	runtime.Spec.IngressClass = opts.IngressClass
	runtime.Spec.IngressController = opts.IngressController.Name()
	runtime.Spec.IngressHost = opts.IngressHost

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

func createEventsReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions) error {
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

func createReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions, reporterCreateOpts reporterCreateOptions) error {
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

	if err := createReporterRBAC(repofs, resPath, opts.RuntimeName, reporterCreateOpts.saName); err != nil {
		return err
	}

	if err := createReporterEventSource(repofs, resPath, opts.RuntimeName, reporterCreateOpts); err != nil {
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

var getProjectInfoFromFile = func(repofs fs.FS, name string) (*argocdv1alpha1.AppProject, *appset.ApplicationSet, error) {
	proj := &argocdv1alpha1.AppProject{}
	appSet := &appset.ApplicationSet{}
	if err := repofs.ReadYamls(name, proj, appSet); err != nil {
		return nil, nil, err
	}

	return proj, appSet, nil
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
		},
		Data: map[string][]byte{
			store.Get().ArgoCDTokenKey: []byte(token),
		},
	})
}

func createReporterRBAC(repofs fs.FS, path, runtimeName, saName string) error {
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

	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: runtimeName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}

	roleBinding := rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: runtimeName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: runtimeName,
				Name:      saName,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
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

func createReporterEventSource(repofs fs.FS, path, namespace string, reporterCreateOpts reporterCreateOptions) error {
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

	for i, name := range resourceNames {
		options.Resource[name] = eventsutil.CreateResourceEventSourceOptions{
			Group:     reporterCreateOpts.gvr[i].group,
			Version:   reporterCreateOpts.gvr[i].version,
			Resource:  reporterCreateOpts.gvr[i].resourceName,
			Namespace: namespace,
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
	var err error

	if opts.InsCloneOpts.Provider == "" {
		if opts.GitIntegrationCreationOpts.Provider, err = inferProviderFromCloneURL(opts.InsCloneOpts.URL()); err != nil {
			return err
		}
	} else {
		opts.GitIntegrationCreationOpts.Provider = apmodel.GitProviders(strings.ToUpper(opts.InsCloneOpts.Provider))
	}

	if opts.GitIntegrationCreationOpts.APIURL == "" {
		if opts.GitIntegrationCreationOpts.APIURL, err = inferAPIURLForGitProvider(opts.GitIntegrationCreationOpts.Provider); err != nil {
			return err
		}
	}

	if opts.GitIntegrationRegistrationOpts.Token == "" {
		return fmt.Errorf("git personal access token is missing")
	}

	return nil
}

func inferProviderFromCloneURL(cloneURL string) (apmodel.GitProviders, error) {
	const suggest = "you can specify a git provider explicitly with --provider"

	if strings.Contains(cloneURL, "github.com") {
		return apmodel.GitProvidersGithub, nil
	}
	if strings.Contains(cloneURL, "gitlab.com") {
		return apmodel.GitProvidersGitlab, nil
	}

	return apmodel.GitProviders(""), fmt.Errorf("failed to infer git provider from clone url: %s, %s", cloneURL, suggest)
}

func inferAPIURLForGitProvider(provider apmodel.GitProviders) (string, error) {
	const suggest = "you can specify a git provider explicitly with --provider-api-url"

	switch provider {
	case apmodel.GitProvidersGithub:
		return "https://api.github.com", nil
	case apmodel.GitProvidersGitlab:
		return "https://gitlab.com/api/v4", nil
	}

	return "", fmt.Errorf("cannot infer api-url for git provider %s, %s", provider, suggest)
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

func handleCliStep(step reporter.CliStep, message string, err error, preStep bool, appendToLog bool) {
	r := reporter.G()
	status := reporter.SUCCESS
	if err != nil {
		if preStep {
			status = reporter.CANCELED
		} else {
			status = reporter.FAILURE
		}
	}

	r.ReportStep(reporter.CliStepData{
		Step:        step,
		Status:      status,
		Description: message,
		Err:         err,
	})

	if appendToLog {
		appendLogToSummary(message, err)
	}
}

func appendLogToSummary(message string, err error) {
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{message, Failed})
	} else {
		summaryArr = append(summaryArr, summaryLog{message, Success})
	}
}

func printSummaryToUser() {
	for i := 0; i < len(summaryArr); i++ {
		if summaryArr[i].level == Success {
			fmt.Printf("%s -> %v%s%v\n", summaryArr[i].message, GREEN, summaryArr[i].level, COLOR_RESET)
		} else if summaryArr[i].level == Failed {
			fmt.Printf("%s -> %v%s%v\n", summaryArr[i].message, RED, summaryArr[i].level, COLOR_RESET)
		} else {
			fmt.Printf("%s\n", summaryArr[i].message)
		}
	}
	//clear array to avoid double printing
	summaryArr = []summaryLog{}
}

func createAnalyticsReporter(ctx context.Context, flow reporter.FlowType, disableTelemetry bool) {
	if disableTelemetry {
		log.G().Debug("Analytics Reporter disabled by the --disable-telemetry flag.")
		return
	}

	user, err := cfConfig.GetCurrentContext().GetUser(ctx)
	// If error, it will default to noop reporter
	if err != nil {
		log.G().Debug("Failed to get user from context")
		return
	}

	url := cfConfig.GetCurrentContext().URL

	if url != store.Get().DefaultAPI {
		log.G().Debug("Not reporting for local env")
		return
	}

	reporter.Init(user, flow)
}

func validateRuntimeName(runtime string) error {
	var err error
	isValid, err := IsValidName(runtime)
	if err != nil {
		err = fmt.Errorf("failed to check the validity of the runtime name: %w", err)
	} else if !isValid {
		err = fmt.Errorf("runtime name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
	}

	return err
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
