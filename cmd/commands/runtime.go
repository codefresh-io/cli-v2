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
	"strings"
	"sync"
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
	"github.com/ghodss/yaml"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kustid "sigs.k8s.io/kustomize/api/resid"
	kusttypes "sigs.k8s.io/kustomize/api/types"
)

type (
	RuntimeInstallOptions struct {
		RuntimeName  string
		RuntimeToken string
		IngressHost  string
		Insecure     bool
		Version      *semver.Version
		GsCloneOpts  *git.CloneOptions
		InsCloneOpts *git.CloneOptions
		KubeFactory  kube.Factory
		CommonConfig *runtime.CommonConfig
	}
	RuntimeUninstallOptions struct {
		RuntimeName string
		Timeout     time.Duration
		CloneOpts   *git.CloneOptions
		KubeFactory kube.Factory
		SkipChecks  bool
	}

	RuntimeUpgradeOptions struct {
		RuntimeName  string
		Version      *semver.Version
		CloneOpts    *git.CloneOptions
		CommonConfig *runtime.CommonConfig
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

	return cmd
}

func NewRuntimeInstallCommand() *cobra.Command {
	var (
		ingressHost  string
		versionStr   string
		f            kube.Factory
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
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
		PreRun: func(_ *cobra.Command, _ []string) {
			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			insCloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				version *semver.Version
				err     error
			)

			ctx := cmd.Context()
			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			isValid, err := IsValid(args[0])
			if err != nil {
				log.G(ctx).Fatal("failed to check the validity of the runtime name")
			}

			if !isValid {
				log.G(ctx).Fatal("runtime name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
			}

			if versionStr != "" {
				version, err = semver.NewVersion(versionStr)
				if err != nil {
					return err
				}
			}

			runtimeName := args[0]
			if gsCloneOpts.Repo == "" {
				host, orgRepo, _, _, _, suffix, _ := aputil.ParseGitUrl(insCloneOpts.Repo)
				gsCloneOpts.Repo = host + orgRepo + "_git-source" + suffix + "/resources" + "_" + runtimeName
			}
			gsCloneOpts.Parse()

			return RunRuntimeInstall(ctx, &RuntimeInstallOptions{
				RuntimeName:  runtimeName,
				IngressHost:  ingressHost,
				Version:      version,
				Insecure:     true,
				GsCloneOpts:  gsCloneOpts,
				InsCloneOpts: insCloneOpts,
				KubeFactory:  f,
				CommonConfig: &runtime.CommonConfig{
					CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
				},
			})
		},
	}

	cmd.Flags().StringVar(&ingressHost, "ingress-host", "", "The ingress host")
	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to install, defaults to latest")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be ready")

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
	})
	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
	})
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func getComponents(rt *runtime.Runtime, opts *RuntimeInstallOptions) []string {
	var componentNames []string
	for _, component := range rt.Spec.Components {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, component.Name)
		componentNames = append(componentNames, componentFullName)
	}

	//  should find a more dynamic way to get these additional components
	additionalComponents := []string{"events-reporter", "workflow-reporter"}
	for _, additionalComponentName := range additionalComponents {
		componentFullName := fmt.Sprintf("%s-%s", opts.RuntimeName, additionalComponentName)
		componentNames = append(componentNames, componentFullName)
	}
	argoCDFullName := store.Get().ArgoCD
	componentNames = append(componentNames, argoCDFullName)

	return componentNames
}

func createRuntimeOnPlatform(ctx context.Context, runtimeName string, server string, runtimeVersion string, ingressHost string, componentNames []string) (string, error) {
	runtimeCreationResponse, err := cfConfig.NewClient().V2().Runtime().Create(ctx, runtimeName, server, runtimeVersion, ingressHost, componentNames)

	if err != nil {
		return "", fmt.Errorf("failed to create a new runtime: %s. Error: %w", runtimeName, err)
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

	token, err := createRuntimeOnPlatform(ctx, opts.RuntimeName, server, runtimeVersion, opts.IngressHost, componentNames)

	if err != nil {
		return fmt.Errorf("failed to create a new runtime: %w", err)
	}

	opts.RuntimeToken = token

	rt.Spec.Cluster = server
	rt.Spec.IngressHost = opts.IngressHost

	log.G(ctx).WithField("version", rt.Spec.Version).Infof("Installing runtime '%s'", opts.RuntimeName)
	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: rt.Spec.FullSpecifier(),
		Namespace:    opts.RuntimeName,
		KubeFactory:  opts.KubeFactory,
		CloneOptions: opts.InsCloneOpts,
		Insecure:     opts.Insecure,
		ArgoCDLabels: map[string]string{
			store.Get().LabelKeyCFType: store.Get().CFComponentType,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to bootstrap repository: %w", err)
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   opts.InsCloneOpts,
		ProjectName: opts.RuntimeName,
		Labels: map[string]string{
			store.Get().LabelKeyCFType: fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFType)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	// persists codefresh-cm, this must be created before events-reporter eventsource
	// otherwise it will not start and no events will get to the platform.
	if err = persistRuntime(ctx, opts.InsCloneOpts, rt, opts.CommonConfig); err != nil {
		return fmt.Errorf("failed to create codefresh-cm: %w", err)
	}

	for _, component := range rt.Spec.Components {
		log.G(ctx).Infof("Creating component '%s'", component.Name)
		if err = component.CreateApp(ctx, opts.KubeFactory, opts.InsCloneOpts, opts.RuntimeName, store.Get().CFComponentType); err != nil {
			return fmt.Errorf("failed to create '%s' application: %w", component.Name, err)
		}
	}

	if opts.IngressHost != "" {
		if err = createWorkflowsIngress(ctx, opts.InsCloneOpts, rt); err != nil {
			return fmt.Errorf("failed to patch Argo-Workflows ingress: %w", err)
		}
	}

	if err = createCodefreshArgoAgentReporter(ctx, opts.InsCloneOpts, opts, rt); err != nil {
		return fmt.Errorf("failed to create argocd-agent-reporter: %w", err)
	}

	if err = createEventsReporter(ctx, opts.InsCloneOpts, opts, rt); err != nil {
		return fmt.Errorf("failed to create events-reporter: %w", err)
	}

	if err = createWorkflowReporter(ctx, opts.InsCloneOpts, opts); err != nil {
		return fmt.Errorf("failed to create workflows-reporter: %w", err)
	}

	gsPath := opts.GsCloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().GitSourceName, opts.RuntimeName)
	fullGsPath := opts.GsCloneOpts.FS.Join(opts.GsCloneOpts.FS.Root(), gsPath)[1:]

	if err = RunGitSourceCreate(ctx, &GitSourceCreateOptions{
		InsCloneOpts: opts.InsCloneOpts,
		GsCloneOpts:  opts.GsCloneOpts,
		GsName:       store.Get().GitSourceName,
		RuntimeName:  opts.RuntimeName,
		FullGsPath:   fullGsPath,
	}); err != nil {
		return fmt.Errorf("failed to create `%s`: %w", store.Get().GitSourceName, err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	err = intervalCheckIsRuntimePersisted(ctx, opts.RuntimeName, &wg)
	if err != nil {
		return fmt.Errorf("failed to complete installation: %w", err)
	}
	wg.Wait()

	log.G(ctx).Infof("Done installing runtime '%s'", opts.RuntimeName)
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

	return fmt.Errorf("argo-cd is already installed on this cluster in namespace '%s', you need to uninstall it first", subjNamespace)
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

func intervalCheckIsRuntimePersisted(ctx context.Context, runtimeName string, wg *sync.WaitGroup) error {
	maxRetries := 60           // up to 10 min
	longerThanUsualCount := 30 // after 5 min
	waitMsg := "Waiting for the runtime installation to complete"
	longetThanUsualMsg := waitMsg + " (this is taking longer than usual, you might need to check your cluster for errors)"
	stop := util.WithSpinner(ctx, waitMsg)
	ticker := time.NewTicker(time.Second * 10)

	for triesLeft := maxRetries; triesLeft > 0; triesLeft, _ = triesLeft-1, <-ticker.C {
		runtime, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
		if err != nil {
			stop()
			return fmt.Errorf("failed to complete the runtime installation. Error: %w", err)
		}

		if runtime.InstallationStatus == model.InstallationStatusCompleted {
			stop()
			wg.Done()
			ticker.Stop()
			return nil
		}

		if triesLeft == longerThanUsualCount {
			stop()
			stop = util.WithSpinner(ctx, longetThanUsualMsg)
		}
	}

	stop()

	return fmt.Errorf("timed out while waiting for runtime installation to complete")
}

func NewRuntimeListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list [runtime_name]",
		Short:   "List all Codefresh runtimes",
		Example: util.Doc(`<BIN> runtime list`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunRuntimeList(cmd.Context())
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
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tVERSION\tSYNC_STATUS\tHEALTH_STATUS\tHEALTH_MESSAGE\tINSTALLATION_STATUS")
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

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			version,
			syncStatus,
			healthStatus,
			healthMessage,
			installationStatus,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func NewRuntimeUninstallCommand() *cobra.Command {
	var (
		skipChecks bool
		f          kube.Factory
		cloneOpts  *git.CloneOptions
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
		PreRun: func(_ *cobra.Command, _ []string) {
			cloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			return RunRuntimeUninstall(ctx, &RuntimeUninstallOptions{
				RuntimeName: args[0],
				Timeout:     store.Get().WaitTimeout,
				CloneOpts:   cloneOpts,
				KubeFactory: f,
				SkipChecks:  skipChecks,
			})
		},
	}

	cmd.Flags().BoolVar(&skipChecks, "skip-checks", false, "If true, will not verify that runtime exists before uninstalling")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be deleted")

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
	}); err != nil {
		return fmt.Errorf("failed uninstalling runtime: %w", err)
	}

	log.G(ctx).Infof("Deleting runtime '%s' from the platform", opts.RuntimeName)

	if _, err := cfConfig.NewClient().V2().Runtime().Delete(ctx, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	log.G(ctx).Infof("Done uninstalling runtime '%s'", opts.RuntimeName)
	return nil
}

func NewRuntimeUpgradeCommand() *cobra.Command {
	var (
		versionStr string
		cloneOpts  *git.CloneOptions
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
		PreRun: func(_ *cobra.Command, _ []string) {
			cloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				version *semver.Version
				err     error
			)
			ctx := cmd.Context()
			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if versionStr != "" {
				version, err = semver.NewVersion(versionStr)
				if err != nil {
					return err
				}
			}

			return RunRuntimeUpgrade(ctx, &RuntimeUpgradeOptions{
				RuntimeName: args[0],
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

	curRt, err := runtime.Load(fs, fs.Join(apstore.Default.BootsrtrapDir, store.Get().RuntimeFilename))
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
		if err = component.CreateApp(ctx, nil, opts.CloneOpts, opts.RuntimeName, store.Get().CFComponentType); err != nil {
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

	overlaysDir := fs.Join(apstore.Default.AppsDir, "workflows", apstore.Default.OverlaysDir, rt.Name)
	ingress := ingressutil.CreateIngress(&ingressutil.CreateIngressOptions{
		Name:        rt.Name + store.Get().IngressName,
		Namespace:   rt.Namespace,
		Path:        store.Get().IngressPath,
		ServiceName: store.Get().ArgoWFServiceName,
		ServicePort: store.Get().ArgoWFServicePort,
	})
	if err = fs.WriteYamls(fs.Join(overlaysDir, "ingress.yaml"), ingress); err != nil {
		return err
	}

	if err = billyUtils.WriteFile(fs, fs.Join(overlaysDir, "ingress-patch.json"), ingressPatch, 0666); err != nil {
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
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType); err != nil {
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

func createWorkflowReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions) error {
	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().WorkflowReporterName, opts.RuntimeName, "resources")
	appDef := &runtime.AppDef{
		Name: store.Get().WorkflowReporterName,
		Type: application.AppTypeDirectory,
		URL:  cloneOpts.URL() + "/" + resPath,
	}
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := createWorkflowReporterRBAC(repofs, resPath, opts.RuntimeName); err != nil {
		return err
	}

	if err := createWorkflowReporterEventSource(repofs, resPath, opts.RuntimeName); err != nil {
		return err
	}

	if err := createSensor(repofs, store.Get().WorkflowReporterName, resPath, opts.RuntimeName, store.Get().WorkflowReporterName, "workflows", "data.object"); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing Codefresh Workflow Reporter mainifests")

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

func createWorkflowReporterRBAC(repofs fs.FS, path, runtimeName string) error {
	serviceAccount := &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().CodefreshSA,
			Namespace: runtimeName,
		},
	}

	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().CodefreshSA,
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
			Name:      store.Get().CodefreshSA,
			Namespace: runtimeName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: runtimeName,
				Name:      store.Get().CodefreshSA,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: store.Get().CodefreshSA,
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

func createWorkflowReporterEventSource(repofs fs.FS, path, namespace string) error {
	eventSource := eventsutil.CreateEventSource(&eventsutil.CreateEventSourceOptions{
		Name:               store.Get().WorkflowReporterName,
		Namespace:          namespace,
		ServiceAccountName: store.Get().CodefreshSA,
		EventBusName:       store.Get().EventBusName,
		Resource: map[string]eventsutil.CreateResourceEventSourceOptions{
			"workflows": {
				Group:     argowf.Group,
				Version:   argowf.Version,
				Resource:  argowf.WorkflowPlural,
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
