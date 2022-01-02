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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	argodashboardutil "github.com/codefresh-io/cli-v2/pkg/util/argo-agent"
	cdutil "github.com/codefresh-io/cli-v2/pkg/util/cd"
	eventsutil "github.com/codefresh-io/cli-v2/pkg/util/events"
	ingressutil "github.com/codefresh-io/cli-v2/pkg/util/ingress"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	apmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model/app-proxy"

	appset "github.com/argoproj-labs/applicationset/api/v1alpha1"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	argowf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"

	"github.com/Masterminds/semver/v3"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"
	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5/memfs"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kustid "sigs.k8s.io/kustomize/api/resid"
	kusttypes "sigs.k8s.io/kustomize/api/types"
)

type (
	RuntimeInstallOptions struct {
		RuntimeName          string
		RuntimeToken         string
		IngressHost          string
		Insecure             bool
		InstallDemoResources bool
		Version              *semver.Version
		GsCloneOpts          *git.CloneOptions
		InsCloneOpts         *git.CloneOptions
		GitIntegrationOpts   *apmodel.AddGitIntegrationArgs
		KubeFactory          kube.Factory
		CommonConfig         *runtime.CommonConfig
		versionStr           string
		kubeContext          string
	}
	RuntimeUninstallOptions struct {
		RuntimeName string
		Timeout     time.Duration
		CloneOpts   *git.CloneOptions
		KubeFactory kube.Factory
		SkipChecks  bool
		Force       bool
		FastExit    bool
	}

	RuntimeUpgradeOptions struct {
		RuntimeName  string
		Version      *semver.Version
		CloneOpts    *git.CloneOptions
		CommonConfig *runtime.CommonConfig
	}
	reporterCreateOptions struct {
		reporterName string
		resourceName string
		group        string
		version      string
		saName       string
	}
)

func NewRuntimeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "runtime",
		Short:             "Manage Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
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
		gitIntegrationOpts = apmodel.AddGitIntegrationArgs{
			SharingPolicy: apmodel.SharingPolicyAllUsersInAccount,
		}
		installationOpts = RuntimeInstallOptions{GitIntegrationOpts: &gitIntegrationOpts}
		finalParameters  map[string]string
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

			if err := runtimeInstallCommandPreRunHandler(cmd, &installationOpts); err != nil {
				return fmt.Errorf("Pre installation error: %w", err)
			}

			finalParameters = map[string]string{
				"Kube context":              installationOpts.kubeContext,
				"Runtime name":              installationOpts.RuntimeName,
				"Repository URL":            installationOpts.InsCloneOpts.Repo,
				"Ingress host":              installationOpts.IngressHost,
				"Installing demo resources": strconv.FormatBool(installationOpts.InstallDemoResources),
			}

			if err := getApprovalFromUser(cmd.Context(), finalParameters, "runtime install"); err != nil {
				return fmt.Errorf("%w", err)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunRuntimeInstall(cmd.Context(), &installationOpts)
		},
	}

	cmd.Flags().StringVar(&installationOpts.IngressHost, "ingress-host", "", "The ingress host")
	cmd.Flags().StringVar(&installationOpts.versionStr, "version", "", "The runtime version to install (default: latest)")
	cmd.Flags().BoolVar(&installationOpts.InstallDemoResources, "demo-resources", true, "Installs demo resources (default: true)")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be ready")
	cmd.Flags().StringVar(&gitIntegrationOpts.APIURL, "provider-api-url", "", "Git provider API url")

	installationOpts.InsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
	})
	installationOpts.GsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
	})
	installationOpts.KubeFactory = kube.AddFlags(cmd.Flags())

	util.Die(cmd.MarkFlagRequired("ingress-host"))

	return cmd
}

func runtimeInstallCommandPreRunHandler(cmd *cobra.Command, opts *RuntimeInstallOptions) error {
	if err := verifyCLILatestVersion(cmd.Context()); err != nil {
		return err
	}

	if opts.versionStr != "" {
		version, err := semver.NewVersion(opts.versionStr)
		if err != nil {
			return err
		}
		opts.Version = version
	}

	if !store.Get().Silent && opts.RuntimeName == "" {
		if err := getRuntimeNameFromUserInput(&opts.RuntimeName); err != nil {
			return err
		}
	}

	if opts.RuntimeName == "" {
		return fmt.Errorf("must enter a runtime name")
	}

	if isValid, err := IsValidName(opts.RuntimeName); err != nil {
		log.G(cmd.Context()).Fatal("failed to check the validity of the runtime name")
	} else if !isValid {
		log.G(cmd.Context()).Fatal("runtime name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
	}

	if err := getKubeContextNameFromUserSelect(cmd, &opts.kubeContext); err != nil {
		return fmt.Errorf("%w", err)
	}

	if err := ensureRepo(cmd, opts.RuntimeName, opts.InsCloneOpts, false); err != nil {
		return err
	}

	if err := ensureGitToken(cmd, opts.InsCloneOpts); err != nil {
		return err
	}

	if err := getIngressHostFromUserInput(cmd, &opts.IngressHost); err != nil {
		return err
	}

	if err := askUserIfToInstallDemoResources(cmd, &opts.InstallDemoResources); err != nil {
		return err
	}

	if opts.GsCloneOpts.Auth.Password == "" {
		opts.GsCloneOpts.Auth.Password = opts.InsCloneOpts.Auth.Password
	}

	if opts.GsCloneOpts.Repo == "" {
		host, orgRepo, _, _, _, suffix, _ := aputil.ParseGitUrl(opts.InsCloneOpts.Repo)
		opts.GsCloneOpts.Repo = host + orgRepo + "_git-source" + suffix + "/resources" + "_" + opts.RuntimeName
	}

	opts.InsCloneOpts.Parse()
	opts.GsCloneOpts.Parse()

	if err := ensureGitIntegrationOpts(opts); err != nil {
		return err
	}

	opts.Insecure = true // installs argo-cd in insecure mode, we need this so that the eventsource can talk to the argocd-server with http
	opts.CommonConfig = &runtime.CommonConfig{CodefreshBaseURL: cfConfig.GetCurrentContext().URL}

	return nil
}

func getComponents(rt *runtime.Runtime, opts *RuntimeInstallOptions) []string {
	var componentNames []string
	for _, component := range rt.Spec.Components {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, component.Name)
		componentNames = append(componentNames, componentFullName)
	}

	//  should find a more dynamic way to get these additional components
	additionalComponents := []string{"events-reporter", "workflow-reporter", "replicaset-reporter"}
	for _, additionalComponentName := range additionalComponents {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, additionalComponentName)
		componentNames = append(componentNames, componentFullName)
	}
	argoCDFullName := store.Get().ArgoCD
	componentNames = append(componentNames, argoCDFullName)

	return componentNames
}

func createRuntimeOnPlatform(ctx context.Context, opts *model.RuntimeInstallationArgs) (string, error) {
	runtimeCreationResponse, err := cfConfig.NewClient().V2().Runtime().Create(ctx, opts)

	if err != nil {
		return "", fmt.Errorf("failed to create a new runtime: %s. Error: %w", opts.RuntimeName, err)
	}

	return runtimeCreationResponse.NewAccessToken, nil
}

func RunRuntimeInstall(ctx context.Context, opts *RuntimeInstallOptions) error {
	if err := preInstallationChecks(ctx, opts); err != nil {
		return fmt.Errorf("pre installation checks failed: %w", err)
	}

	rt, err := runtime.Download(opts.Version, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	runtimeVersion := "v99.99.99"
	if rt.Spec.Version != nil { // in dev mode
		runtimeVersion = rt.Spec.Version.String()
	}

	server, err := util.CurrentServer()
	if err != nil {
		return fmt.Errorf("failed to get current server address: %w", err)
	}

	componentNames := getComponents(rt, opts)

	token, err := createRuntimeOnPlatform(ctx, &model.RuntimeInstallationArgs{
		RuntimeName:    opts.RuntimeName,
		Cluster:        server,
		RuntimeVersion: runtimeVersion,
		IngressHost:    &opts.IngressHost,
		ComponentNames: componentNames,
		Repo:           &opts.InsCloneOpts.Repo,
	})
	if err != nil {
		return fmt.Errorf("failed to create a new runtime: %w", err)
	}

	opts.RuntimeToken = token
	rt.Spec.Cluster = server
	rt.Spec.IngressHost = opts.IngressHost
	rt.Spec.Repo = opts.InsCloneOpts.Repo

	var installationErr error

	defer reportInstallationErrorToPlatform(ctx, opts.RuntimeName, &installationErr)

	log.G(ctx).WithField("version", rt.Spec.Version).Infof("Installing runtime '%s'", opts.RuntimeName)
	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: 	 rt.Spec.FullSpecifier(),
		Namespace:       opts.RuntimeName,
		KubeFactory:     opts.KubeFactory,
		CloneOptions:    opts.InsCloneOpts,
		Insecure:     	 opts.Insecure,
		KubeContextName: opts.kubeContext,
		ArgoCDLabels: map[string]string{
			store.Get().LabelKeyCFType: store.Get().CFComponentType,
		},
	})
	if err != nil {
		installationErr = fmt.Errorf("failed to bootstrap repository: %w", err)
		return installationErr
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   opts.InsCloneOpts,
		ProjectName: opts.RuntimeName,
		Labels: map[string]string{
			store.Get().LabelKeyCFType: fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFType)),
		},
	})
	if err != nil {
		installationErr = fmt.Errorf("failed to create project: %w", err)
		return installationErr
	}

	// persists codefresh-cm, this must be created before events-reporter eventsource
	// otherwise it will not start and no events will get to the platform.
	if err = persistRuntime(ctx, opts.InsCloneOpts, rt, opts.CommonConfig); err != nil {
		installationErr = fmt.Errorf("failed to create codefresh-cm: %w", err)
		return installationErr
	}

	for _, component := range rt.Spec.Components {
		log.G(ctx).Infof("Creating component '%s'", component.Name)
		if err = component.CreateApp(ctx, opts.KubeFactory, opts.InsCloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", ""); err != nil {
			installationErr = fmt.Errorf("failed to create '%s' application: %w", component.Name, err)
			return installationErr
		}
	}

	err = installComponents(ctx, opts, rt)
	if err != nil {
		installationErr = fmt.Errorf("failed to install components: %s", err)
		return installationErr
	}

	if err = RunGitSourceCreate(ctx, &GitSourceCreateOptions{
		InsCloneOpts:        opts.InsCloneOpts,
		GsCloneOpts:         opts.GsCloneOpts,
		GsName:              store.Get().GitSourceName,
		RuntimeName:         opts.RuntimeName,
		CreateDemoResources: opts.InstallDemoResources,
	}); err != nil {
		installationErr = fmt.Errorf("failed to create `%s`: %w", store.Get().GitSourceName, err)
		return installationErr
	}

	mpCloneOpts := &git.CloneOptions{
		Repo: store.Get().MarketplaceRepo,
		FS:   fs.Create(memfs.New()),
	}
	mpCloneOpts.Parse()
	if err = RunGitSourceCreate(ctx, &GitSourceCreateOptions{
		InsCloneOpts:        opts.InsCloneOpts,
		GsCloneOpts:         mpCloneOpts,
		GsName:              store.Get().MarketplaceGitSourceName,
		RuntimeName:         opts.RuntimeName,
		CreateDemoResources: false,
		Exclude:             "**/images/**/*",
		Include:             "workflows/**/*.yaml",
	}); err != nil {
		installationErr = fmt.Errorf("failed to create `%s`: %w", store.Get().MarketplaceGitSourceName, err)
		return installationErr
	}

	if err = intervalCheckIsRuntimePersisted(ctx, opts.RuntimeName); err != nil {
		installationErr = fmt.Errorf("failed to complete installation: %w", err)
		return installationErr
	}

	if err := addDefaultGitIntegration(ctx, opts.RuntimeName, opts.GitIntegrationOpts); err != nil {
		return fmt.Errorf("failed to create default git integration: %w", err)
	}

	log.G(ctx).Infof("Runtime '%s' installed successfully", opts.RuntimeName)

	return nil
}

func addDefaultGitIntegration(ctx context.Context, runtime string, opts *apmodel.AddGitIntegrationArgs) error {
	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, runtime)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client: %w", err)
	}

	if err := RunGitIntegrationAddCommand(ctx, appProxyClient, opts); err != nil {
		return err
	}

	log.G(ctx).Info("Added default git integration")

	return nil
}

func reportInstallationErrorToPlatform(ctx context.Context, runtime string, err *error) {
	if *err == nil {
		return
	}

	installationError := &model.HealthErrorInput{
		Level:   model.ErrorLevelsError,
		Message: (*err).Error(),
	}
	_, err1 := cfConfig.NewClient().V2().Runtime().ReportErrors(ctx, &model.ReportRuntimeErrorsArgs{
		Runtime: runtime,
		Errors:  []*model.HealthErrorInput{installationError},
	})

	if err1 != nil {
		log.G(ctx).Errorf("failed to report installation errors of runtime: %s. Error: %s", runtime, err1)
	}
}

func installComponents(ctx context.Context, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	var err error
	if opts.IngressHost != "" {
		if err = createWorkflowsIngress(ctx, opts.InsCloneOpts, rt); err != nil {
			return fmt.Errorf("failed to patch Argo-Workflows ingress: %w", err)
		}
	}

	if err = configureAppProxy(ctx, opts, rt); err != nil {
		return fmt.Errorf("failed to patch App-Proxy ingress: %w", err)
	}

	if err = createCodefreshArgoAgentReporter(ctx, opts.InsCloneOpts, opts, rt); err != nil {
		return fmt.Errorf("failed to create argocd-agent-reporter: %w", err)
	}

	if err = createEventsReporter(ctx, opts.InsCloneOpts, opts, rt); err != nil {
		return fmt.Errorf("failed to create events-reporter: %w", err)
	}

	if err = createReporter(
		ctx, opts.InsCloneOpts, opts, reporterCreateOptions{
			reporterName: store.Get().WorkflowReporterName,
			resourceName: store.Get().WorkflowResourceName,
			group:        argowf.Group,
			version:      argowf.Version,
			saName:       store.Get().CodefreshSA,
		}); err != nil {
		return fmt.Errorf("failed to create workflows-reporter: %w", err)
	}

	if err = createReporter(ctx, opts.InsCloneOpts, opts, reporterCreateOptions{
		reporterName: store.Get().ReplicaSetReporterName,
		resourceName: store.Get().ReplicaSetResourceName,
		group:        "apps",
		version:      "v1",
		saName:       store.Get().ReplicaSetReporterServiceAccount,
	}); err != nil {
		return fmt.Errorf("failed to create replicaset-reporter: %w", err)
	}

	return nil
}

func preInstallationChecks(ctx context.Context, opts *RuntimeInstallOptions) error {
	log.G(ctx).Debug("running pre-installation checks...")

	if err := checkRuntimeCollisions(ctx, opts.RuntimeName, opts.KubeFactory); err != nil {
		return fmt.Errorf("runtime collision check failed: %w", err)
	}

	if err := checkExistingRuntimes(ctx, opts.RuntimeName); err != nil {
		return fmt.Errorf("existing runtime check failed: %w", err)
	}

	err := kubeutil.EnsureClusterRequirements(ctx, opts.KubeFactory, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("validation of minimum cluster requirements failed: %v ", err))
	}

	return nil
}

func checkRuntimeCollisions(ctx context.Context, runtime string, kube kube.Factory) error {
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

		return fmt.Errorf("failed to get cluster-role-binding '%s': %w", store.Get().ArgoCDServerName, err)
	}

	log.G(ctx).Debug("argocd cluster-role-binding found")

	if len(crb.Subjects) == 0 {
		return nil // no collision
	}

	subjNamespace := crb.Subjects[0].Namespace

	// check if some argocd is actually using this crb
	_, err = cs.AppsV1().Deployments(subjNamespace).Get(ctx, store.Get().ArgoCDServerName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.G(ctx).Debug("argocd cluster-role-binding subject does not exist, no collision")

			return nil // no collision
		}

		return fmt.Errorf("failed to get deployment '%s': %w", store.Get().ArgoCDServerName, err)
	}

	return fmt.Errorf("argo-cd is already installed on this cluster in namespace '%s', you can uninstall it by running '%s runtime uninstall %s --skip-checks --force'", subjNamespace, store.Get().BinaryName, subjNamespace)
}

func checkExistingRuntimes(ctx context.Context, runtime string) error {
	_, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtime)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil // runtime does not exist
		}

		return fmt.Errorf("failed to get runtime: %w", err)
	}

	return fmt.Errorf("runtime '%s' already exists", runtime)
}

func intervalCheckIsRuntimePersisted(ctx context.Context, runtimeName string) error {
	maxRetries := 180 // up to 30 min
	waitMsg := "Waiting for the runtime installation to complete"
	stop := util.WithSpinner(ctx, waitMsg)
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	defer stop()

	for triesLeft := maxRetries; triesLeft > 0; triesLeft, _ = triesLeft-1, <-ticker.C {
		runtime, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
		if err != nil {
			return fmt.Errorf("failed to complete the runtime installation. Error: %w", err)
		}

		if runtime.InstallationStatus == model.InstallationStatusCompleted {
			return nil
		}
	}

	return fmt.Errorf("timed out while waiting for runtime installation to complete")
}

func NewRuntimeListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list [runtime_name]",
		Aliases: []string{"ls"},
		Short:   "List all Codefresh runtimes",
		Example: util.Doc(`<BIN> runtime list`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return fmt.Errorf("%w", err)
			}
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

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			version,
			syncStatus,
			healthStatus,
			healthMessage,
			installationStatus,
			ingressHost,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func NewRuntimeUninstallCommand() *cobra.Command {
	var (
		kubeContextName string
		runtimeName     string
		skipChecks      bool
		f               kube.Factory
		cloneOpts       *git.CloneOptions
		force           bool
		fastExit        bool
		finalParameters map[string]string
	)

	cmd := &cobra.Command{
		Use:   "uninstall [runtime_name]",
		Short: "Uninstall a Codefresh runtime",
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

			if err := verifyCLILatestVersion(ctx); err != nil {
				return fmt.Errorf("%w", err)
			}

			err := getKubeContextNameFromUserSelect(cmd, &kubeContextName)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			err = ensureRuntimeName(ctx, args, &runtimeName)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			err = ensureRepo(cmd, runtimeName, cloneOpts, true)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			err = ensureGitToken(cmd, cloneOpts)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			finalParameters = map[string]string{
				"Kube context":   kubeContextName,
				"Runtime name":   runtimeName,
				"Repository URL": cloneOpts.Repo,
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime uninstall")
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			cloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunRuntimeUninstall(ctx, &RuntimeUninstallOptions{
				RuntimeName: runtimeName,
				Timeout:     store.Get().WaitTimeout,
				CloneOpts:   cloneOpts,
				KubeFactory: f,
				SkipChecks:  skipChecks,
				Force:       force,
				FastExit:    fastExit,
			})
		},
	}

	cmd.Flags().BoolVar(&skipChecks, "skip-checks", false, "If true, will not verify that runtime exists before uninstalling")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be deleted")
	cmd.Flags().BoolVar(&force, "force", false, "If true, will guarantee the runtime is removed from the platform, even in case of errors while cleaning the repo and the cluster")
	cmd.Flags().BoolVar(&fastExit, "fast-exit", false, "If true, will not wait for deletion of cluster resources. This means that full resource deletion will not be verified")

	cloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{})
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeUninstall(ctx context.Context, opts *RuntimeUninstallOptions) error {
	// check whether the runtime exists
	if !opts.SkipChecks {
		_, err := cfConfig.NewClient().V2().Runtime().Get(ctx, opts.RuntimeName)
		if err != nil {
			log.G(ctx).Warn("you can attempt to uninstall again with the \"--skip-checks\" flag")
			return err
		}
	}

	log.G(ctx).Infof("Uninstalling runtime '%s'", opts.RuntimeName)

	if err := apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
		Namespace:    opts.RuntimeName,
		Timeout:      opts.Timeout,
		CloneOptions: opts.CloneOpts,
		KubeFactory:  opts.KubeFactory,
		Force:        opts.Force,
		FastExit:     opts.FastExit,
	}); err != nil {
		if !opts.Force {
			log.G(ctx).Warn("you can attempt to uninstall again with the \"--force\" flag")
			return err
		}
	}

	if err := deleteRuntimeFromPlatform(ctx, opts); err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	if cfConfig.GetCurrentContext().DefaultRuntime == opts.RuntimeName {
		cfConfig.GetCurrentContext().DefaultRuntime = ""
	}

	log.G(ctx).Infof("Done uninstalling runtime '%s'", opts.RuntimeName)

	return nil
}

func deleteRuntimeFromPlatform(ctx context.Context, opts *RuntimeUninstallOptions) error {
	log.G(ctx).Infof("Deleting runtime '%s' from the platform", opts.RuntimeName)
	_, err := cfConfig.NewClient().V2().Runtime().Delete(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Successfully deleted runtime '%s' from the platform", opts.RuntimeName)
	return nil
}

func NewRuntimeUpgradeCommand() *cobra.Command {
	var (
		runtimeName     string
		versionStr      string
		cloneOpts       *git.CloneOptions
		finalParameters map[string]string
	)

	cmd := &cobra.Command{
		Use:   "upgrade [runtime_name]",
		Short: "Upgrade a Codefresh runtime",
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

			if err := verifyCLILatestVersion(ctx); err != nil {
				return fmt.Errorf("%w", err)
			}

			err := ensureRuntimeName(ctx, args, &runtimeName)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			err = ensureRepo(cmd, runtimeName, cloneOpts, true)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			err = ensureGitToken(cmd, cloneOpts)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			finalParameters = map[string]string{
				"Runtime name":   runtimeName,
				"Repository URL": cloneOpts.Repo,
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime upgrade")
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			cloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				version *semver.Version
				err     error
			)
			ctx := cmd.Context()

			if versionStr != "" {
				version, err = semver.NewVersion(versionStr)
				if err != nil {
					return err
				}
			}

			return RunRuntimeUpgrade(ctx, &RuntimeUpgradeOptions{
				RuntimeName: runtimeName,
				Version:     version,
				CloneOpts:   cloneOpts,
				CommonConfig: &runtime.CommonConfig{
					CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
				},
			})
		},
	}

	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to upgrade to, defaults to latest")
	cloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{})

	return cmd
}

func RunRuntimeUpgrade(ctx context.Context, opts *RuntimeUpgradeOptions) error {
	newRt, err := runtime.Download(opts.Version, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	if newRt.Spec.DefVersion.GreaterThan(store.Get().MaxDefVersion) {
		return fmt.Errorf("please upgrade your cli version before upgrading to %s", newRt.Spec.Version)
	}

	r, fs, err := opts.CloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	curRt, err := runtime.Load(fs, fs.Join(apstore.Default.BootsrtrapDir, opts.RuntimeName+".yaml"))
	if err != nil {
		return fmt.Errorf("failed to load current runtime definition: %w", err)
	}

	if !newRt.Spec.Version.GreaterThan(curRt.Spec.Version) {
		return fmt.Errorf("must upgrade to version > %s", curRt.Spec.Version)
	}

	newComponents, err := curRt.Upgrade(fs, newRt, opts.CommonConfig)
	if err != nil {
		return fmt.Errorf("failed to upgrade runtime: %w", err)
	}

	log.G(ctx).Info("Pushing new runtime definition")
	if err := apu.PushWithMessage(ctx, r, fmt.Sprintf("Upgraded to %s", newRt.Spec.Version)); err != nil {
		return err
	}

	for _, component := range newComponents {
		log.G(ctx).Infof("Creating app '%s'", component.Name)
		if err = component.CreateApp(ctx, nil, opts.CloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", ""); err != nil {
			return fmt.Errorf("failed to create '%s' application: %w", component.Name, err)
		}
	}

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

func createWorkflowsIngress(ctx context.Context, cloneOpts *git.CloneOptions, rt *runtime.Runtime) error {
	r, fs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	overlaysDir := fs.Join(apstore.Default.AppsDir, store.Get().WorkflowsIngressPath, apstore.Default.OverlaysDir, rt.Name)
	ingress := ingressutil.CreateIngress(&ingressutil.CreateIngressOptions{
		Name:      rt.Name + store.Get().WorkflowsIngressName,
		Namespace: rt.Namespace,
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
	})
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
			KrmId: kusttypes.KrmId{
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
		fmt.Sprintf("cfHost=%s", cfConfig.GetCurrentContext().URL),
		"argoWorkflowsInsecure=true",
	}

	if cfConfig.GetCurrentContext().IsProduction() {
		literalResources = append(literalResources, "env=production")
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

	if opts.IngressHost != "" {
		ingress := ingressutil.CreateIngress(&ingressutil.CreateIngressOptions{
			Name:      rt.Name + store.Get().AppProxyIngressName,
			Namespace: rt.Namespace,
			Paths: []ingressutil.IngressPath{
				{
					Path:        fmt.Sprintf("/%s/", store.Get().AppProxyIngressPath),
					PathType:    netv1.PathTypeImplementationSpecific,
					ServiceName: store.Get().AppProxyServiceName,
					ServicePort: store.Get().AppProxyServicePort,
				},
			},
		})
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

func createEventsReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	runtimeTokenSecret, err := getRuntimeTokenSecret(opts.RuntimeName, opts.RuntimeToken)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	argoTokenSecret, err := getArgoCDTokenSecret(ctx, opts.RuntimeName, opts.Insecure)
	if err != nil {
		return fmt.Errorf("failed to create argocd token secret: %w", err)
	}

	argoAgentCFTokenSecret, err := getArgoCDAgentTokenSecret(ctx, cfConfig.GetCurrentContext().Token, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create argocd token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, aputil.JoinManifests(runtimeTokenSecret, argoTokenSecret, argoAgentCFTokenSecret)); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().EventsReporterName, opts.RuntimeName, "resources")
	appDef := &runtime.AppDef{
		Name: store.Get().EventsReporterName,
		Type: application.AppTypeDirectory,
		URL:  cloneOpts.URL() + "/" + resPath,
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

	if err := createSensor(repofs, store.Get().EventsReporterName, resPath, opts.RuntimeName, store.Get().EventsReporterName, "events", "data"); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Event Reporter manifests")

	return apu.PushWithMessage(ctx, r, "Created Codefresh Event Reporter")
}

func createCodefreshArgoAgentReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions, rt *runtime.Runtime) error {
	argoAgentCFTokenSecret, err := getArgoCDAgentTokenSecret(ctx, cfConfig.GetCurrentContext().Token, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create argocd token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, aputil.JoinManifests(argoAgentCFTokenSecret)); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().ArgoCDAgentReporterName, "base")

	r, _, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := createCodefreshArgoDashboardAgent(ctx, resPath, cloneOpts, rt); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing ArgoCD Agent manifests")

	return apu.PushWithMessage(ctx, r, "Created ArgoCD Agent Reporter")
}

func createReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions, reporterCreateOpts reporterCreateOptions) error {
	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, reporterCreateOpts.reporterName, opts.RuntimeName, "resources")
	appDef := &runtime.AppDef{
		Name: reporterCreateOpts.reporterName,
		Type: application.AppTypeDirectory,
		URL:  cloneOpts.URL() + "/" + resPath,
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

	if err := createSensor(repofs, reporterCreateOpts.reporterName, resPath, opts.RuntimeName, reporterCreateOpts.reporterName, reporterCreateOpts.resourceName, "data.object"); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Codefresh ", strings.Title(reporterCreateOpts.reporterName), " mainifests")

	return apu.PushWithMessage(ctx, r, "Created Codefresh Workflow Reporter")
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

func getRuntimeTokenSecret(namespace string, token string) ([]byte, error) {
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
			store.Get().CFTokenSecretKey: []byte(token),
		},
	})
}

func getArgoCDTokenSecret(ctx context.Context, namespace string, insecure bool) ([]byte, error) {
	token, err := cdutil.GenerateToken(ctx, namespace, "admin", nil, insecure)
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

func getArgoCDAgentTokenSecret(ctx context.Context, token string, namespace string) ([]byte, error) {
	return yaml.Marshal(&v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ArgoCDAgentCFTokenSecret,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			store.Get().ArgoCDAgentCFTokenKey: []byte(token),
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
	eventSource := eventsutil.CreateEventSource(&eventsutil.CreateEventSourceOptions{
		Name:               reporterCreateOpts.reporterName,
		Namespace:          namespace,
		ServiceAccountName: reporterCreateOpts.saName,
		EventBusName:       store.Get().EventBusName,
		Resource: map[string]eventsutil.CreateResourceEventSourceOptions{
			"workflows": {
				Group:     reporterCreateOpts.group,
				Version:   reporterCreateOpts.version,
				Resource:  reporterCreateOpts.resourceName,
				Namespace: namespace,
			},
		},
	})
	return repofs.WriteYamls(repofs.Join(path, "event-source.yaml"), eventSource)
}

func createSensor(repofs fs.FS, name, path, namespace, eventSourceName, trigger, dataKey string) error {
	sensor := eventsutil.CreateSensor(&eventsutil.CreateSensorOptions{
		Name:            name,
		Namespace:       namespace,
		EventSourceName: eventSourceName,
		EventBusName:    store.Get().EventBusName,
		TriggerURL:      cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
		Triggers:        []string{trigger},
		TriggerDestKey:  dataKey,
	})
	return repofs.WriteYamls(repofs.Join(path, "sensor.yaml"), sensor)
}

func createCodefreshArgoDashboardAgent(ctx context.Context, path string, cloneOpts *git.CloneOptions, rt *runtime.Runtime) error {
	_, fs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	kust := argodashboardutil.CreateAgentResourceKustomize(&argodashboardutil.CreateAgentOptions{Namespace: rt.Namespace, Name: rt.Name})

	if err = kustutil.WriteKustomization(fs, &kust, path); err != nil {
		return err
	}

	return nil
}

func ensureGitIntegrationOpts(opts *RuntimeInstallOptions) error {
	var err error
	if opts.InsCloneOpts.Provider == "" {
		if opts.GitIntegrationOpts.Provider, err = inferProviderFromCloneURL(opts.InsCloneOpts.URL()); err != nil {
			return err
		}
	}

	if opts.GitIntegrationOpts.APIURL == "" {
		if opts.GitIntegrationOpts.APIURL, err = inferAPIURLForGitProvider(opts.GitIntegrationOpts.Provider); err != nil {
			return err
		}
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
