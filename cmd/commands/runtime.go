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
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	cdutil "github.com/codefresh-io/cli-v2/pkg/util/cd"
	eventsutil "github.com/codefresh-io/cli-v2/pkg/util/events"

	"github.com/Masterminds/semver/v3"
	appset "github.com/argoproj-labs/applicationset/api/v1alpha1"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	wf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	RuntimeInstallOptions struct {
		RuntimeName  string
		RuntimeToken string
		Insecure     bool
		Version      *semver.Version
		gsCloneOpts  *git.CloneOptions
		insCloneOpts *git.CloneOptions
		KubeFactory  kube.Factory
		commonConfig *runtime.CommonConfig
	}

	RuntimeUninstallOptions struct {
		RuntimeName string
		Timeout     time.Duration
		CloneOpts   *git.CloneOptions
		KubeFactory kube.Factory
	}

	RuntimeUpgradeOptions struct {
		RuntimeName  string
		Version      *semver.Version
		CloneOpts    *git.CloneOptions
		commonConfig *runtime.CommonConfig
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
	cmd.AddCommand(NewRuntimeUninsatllCommand())
	cmd.AddCommand(NewRuntimeUpgradeCommand())

	return cmd
}

func NewRuntimeInstallCommand() *cobra.Command {
	var (
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

		export INSTALL_GIT_TOKEN=<token>

# or with the flag:

		--install-git-token <token>

# Adds a new runtime

	<BIN> runtime install runtime-name --install-repo gitops_repo
`),
		PreRun: func(_ *cobra.Command, _ []string) {
			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			insCloneOpts.Parse()
			if gsCloneOpts.Repo == "" {
				host, orgRepo, _, _, _, suffix, _ := aputil.ParseGitUrl(insCloneOpts.Repo)
				gsCloneOpts.Repo = host + orgRepo + "_git_source" + suffix
			}

			gsCloneOpts.Parse()
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

			return RunRuntimeInstall(ctx, &RuntimeInstallOptions{
				RuntimeName:  args[0],
				Version:      version,
				Insecure:     true,
				gsCloneOpts:  gsCloneOpts,
				insCloneOpts: insCloneOpts,
				KubeFactory:  f,
				commonConfig: &runtime.CommonConfig{
					CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
				},
			})
		},
	}

	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to install, defaults to latest")
	insCloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		CreateIfNotExist: true,
		FS:               memfs.New(),
	})
	gsCloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
		FS:               memfs.New(),
	})
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeInstall(ctx context.Context, opts *RuntimeInstallOptions) error {
	rt, err := runtime.Download(opts.Version, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	runtimeCreationResponse, err := cfConfig.NewClient().ArgoRuntime().Create(opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create a new runtime: %w", err)
	}

	opts.RuntimeToken = runtimeCreationResponse.NewAccessToken

	log.G(ctx).WithField("version", rt.Spec.Version).Infof("installing runtime '%s'", opts.RuntimeName)
	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: rt.Spec.FullSpecifier(),
		Namespace:    opts.RuntimeName,
		KubeFactory:  opts.KubeFactory,
		CloneOptions: opts.insCloneOpts,
		Insecure:     opts.Insecure,
	})
	if err != nil {
		return fmt.Errorf("failed to bootstrap repository: %w", err)
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   opts.insCloneOpts,
		ProjectName: opts.RuntimeName,
		Labels: map[string]string{
			store.Get().LabelKeyCFType: fmt.Sprintf("{{ labels.%s }}", util.EscapeAppsetFieldName(store.Get().LabelKeyCFType)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	for _, component := range rt.Spec.Components {
		log.G(ctx).Infof("creating component '%s'", component.Name)
		if err = component.CreateApp(ctx, opts.KubeFactory, opts.insCloneOpts, opts.RuntimeName, store.Get().CFComponentType, rt.Spec.Version); err != nil {
			return fmt.Errorf("failed to create '%s' application: %w", component.Name, err)
		}
	}

	if err = persistRuntime(ctx, opts.insCloneOpts, rt, opts.commonConfig); err != nil {
		return fmt.Errorf("failed to create codefresh-cm: %w", err)
	}

	if err = createEventsReporter(ctx, opts.insCloneOpts, opts); err != nil {
		return fmt.Errorf("failed to create events-reporter: %w", err)
	}

	if err = createWorkflowReporter(ctx, opts.insCloneOpts, opts); err != nil {
		return fmt.Errorf("failed to create workflows-reporter: %w", err)
	}

	if err = createDemoWorkflowTemplate(ctx, opts.gsCloneOpts, store.Get().GitSourceName, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create demo workflowTemplate: %w", err)
	}

	if err = createGitSource(ctx, opts.insCloneOpts, opts.gsCloneOpts, store.Get().GitSourceName, opts.RuntimeName,
		opts.commonConfig.CodefreshBaseURL); err != nil {
		return fmt.Errorf("failed to create `%s`: %w", store.Get().GitSourceName, err)
	}

	log.G(ctx).Infof("done installing runtime '%s'", opts.RuntimeName)
	return nil
}

func NewRuntimeListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list ",
		Short:   "List all Codefresh runtimes",
		Example: util.Doc(`<BIN> runtime list`),
		RunE: func(_ *cobra.Command, _ []string) error {
			return RunRuntimeList()
		},
	}
	return cmd
}

func RunRuntimeList() error {
	runtimes, err := cfConfig.NewClient().ArgoRuntime().List()
	if err != nil {
		return err
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tSTATUS\tVERSION")
	if err != nil {
		return err
	}

	for _, rt := range runtimes {
		status := "N/A"
		namespace := "N/A"
		cluster := "N/A"
		name := "N/A"
		version := "N/A"

		if rt.HealthMessage != nil {
			status = *rt.HealthMessage
		}

		if rt.Metadata.Namespace != "" {
			namespace = rt.Metadata.Namespace
		}

		if rt.Cluster != "" {
			cluster = rt.Cluster
		}

		if rt.Metadata.Name != "" {
			name = rt.Metadata.Name
		}

		if rt.RuntimeVersion != "" {
			version = rt.RuntimeVersion
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			status,
			version,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func NewRuntimeUninsatllCommand() *cobra.Command {
	var (
		f         kube.Factory
		cloneOpts *git.CloneOptions
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
				Timeout:     aputil.MustParseDuration(cmd.Flag("request-timeout").Value.String()),
				CloneOpts:   cloneOpts,
				KubeFactory: f,
			})
		},
	}

	cloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		FS: memfs.New(),
	})
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeUninstall(ctx context.Context, opts *RuntimeUninstallOptions) error {
	log.G(ctx).Infof("uninstalling runtime '%s'", opts.RuntimeName)
	err := apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
		Namespace:    opts.RuntimeName,
		Timeout:      opts.Timeout,
		CloneOptions: opts.CloneOpts,
		KubeFactory:  opts.KubeFactory,
	})
	if err != nil {
		return fmt.Errorf("failed uninstalling runtime: %w", err)
	}

	log.G(ctx).Infof("done uninstalling runtime '%s'", opts.RuntimeName)
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
				commonConfig: &runtime.CommonConfig{
					CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
				},
			})
		},
	}

	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to upgrade to, defaults to latest")
	cloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		FS: memfs.New(),
	})

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

	newComponents, err := curRt.Upgrade(fs, newRt, opts.commonConfig)
	if err != nil {
		return fmt.Errorf("failed to upgrade runtime: %w", err)
	}

	if _, err = r.Persist(ctx, &git.PushOptions{CommitMsg: fmt.Sprintf("Upgraded to %s", newRt.Spec.Version)}); err != nil {
		return err
	}

	for _, component := range newComponents {
		log.G(ctx).Infof("Creating app '%s'", component.Name)
		if err = component.CreateApp(ctx, nil, opts.CloneOpts, opts.RuntimeName, store.Get().CFComponentType, newRt.Spec.Version); err != nil {
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

	if err = rt.Save(fs, fs.Join(apstore.Default.BootsrtrapDir, store.Get().RuntimeFilename), rtConf); err != nil {
		return err
	}

	_, err = r.Persist(ctx, &git.PushOptions{
		CommitMsg: "Persisted runtime data",
	})
	return err
}

func createEventsReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions) error {
	runtimeTokenSecret, err := getRuntimeTokenSecret(opts.RuntimeName, opts.RuntimeToken)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	argoTokenSecret, err := getArgoCDTokenSecret(ctx, opts.RuntimeName, opts.Insecure)
	if err != nil {
		return fmt.Errorf("failed to create argocd token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, aputil.JoinManifests(runtimeTokenSecret, argoTokenSecret)); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().EventsReporterName, opts.RuntimeName, "resources")
	appDef := &runtime.AppDef{
		Name: store.Get().EventsReporterName,
		Type: application.AppTypeDirectory,
		URL:  cloneOpts.URL() + "/" + resPath,
	}
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType, nil); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := updateProject(repofs, opts.RuntimeName); err != nil {
		return err
	}

	if err := createEventsReporterEventSource(repofs, resPath, opts.RuntimeName, opts.Insecure); err != nil {
		return err
	}

	if err := createSensor(repofs, store.Get().EventsReporterName, resPath, opts.RuntimeName, store.Get().EventsReporterName, "events", "data"); err != nil {
		return err
	}

	_, err = r.Persist(ctx, &git.PushOptions{
		CommitMsg: "Created Codefresh Event Reporter",
	})
	return err
}

func createWorkflowReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeInstallOptions) error {
	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().WorkflowReporterName, opts.RuntimeName, "resources")
	appDef := &runtime.AppDef{
		Name: store.Get().WorkflowReporterName,
		Type: application.AppTypeDirectory,
		URL:  cloneOpts.URL() + "/" + resPath,
	}
	if err := appDef.CreateApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().CFComponentType, opts.Version); err != nil {
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

	_, err = r.Persist(ctx, &git.PushOptions{
		CommitMsg: "Created Codefresh Workflow Reporter",
	})
	return err
}

func updateProject(repofs fs.FS, runtimeName string) error {
	projPath := repofs.Join(apstore.Default.ProjectsDir, runtimeName+".yaml")
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
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "workflows",
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

func createDemoWorkflowTemplate(ctx context.Context, gsCloneOpts *git.CloneOptions, gsName, runtimeName string) error {
	gsRepo, gsFs, err := gsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	gsPath := gsCloneOpts.FS.Join(apstore.Default.AppsDir, gsName, runtimeName)
	wfTemplate := &wfv1alpha1.WorkflowTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       wf.WorkflowTemplateKind,
			APIVersion: wfv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-workflow-template",
			Namespace: runtimeName,
		},
		Spec: wfv1alpha1.WorkflowTemplateSpec{
			WorkflowSpec: wfv1alpha1.WorkflowSpec{
				Entrypoint: "whalesay",
				Templates: []wfv1alpha1.Template{
					{
						Name: "whalesay",
						Container: &v1.Container{
							Image:   "docker/whalesay",
							Command: []string{"cowsay"},
							Args:    []string{"Hello World"},
						},
					},
				},
			},
		},
	}
	if err = gsFs.WriteYamls(gsFs.Join(gsPath, "demo-wf-template.yaml"), wfTemplate); err != nil {
		return err
	}

	_, err = gsRepo.Persist(ctx, &git.PushOptions{
		CommitMsg: fmt.Sprintf("Created %s Directory", gsPath),
	})
	return err
}

func createGitSource(ctx context.Context, insCloneOpts *git.CloneOptions, gsCloneOpts *git.CloneOptions, gsName, runtimeName, cfBaseURL string) error {
	var err error

	insRepo, insFs, err := insCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	resPath := insFs.Join(apstore.Default.AppsDir, gsName, runtimeName, "resources")
	eventSourceName := gsName + "-event-source"
	gsSyncName := gsName + "-synchronize"
	selectors := []eventsutil.CreateSelectorOptions{
		{
			Key:       "app.kubernetes.io/instance",
			Operation: "==",
			Value:     gsSyncName,
		},
	}
	eventSource := eventsutil.CreateEventSource(&eventsutil.CreateEventSourceOptions{
		Name:               eventSourceName,
		Namespace:          runtimeName,
		ServiceAccountName: store.Get().CodefreshSA,
		EventBusName:       store.Get().EventBusName,
		Resource: map[string]eventsutil.CreateResourceEventSourceOptions{
			// "clusterWorkflowTemplate": {
			// 	Group:     "argoproj.io",
			// 	Version:   "v1alpha1",
			// 	Resource:  "clusterworkflowtemplates",
			// 	Namespace: runtimeName,
			// 	Selectors: selectors,
			// },
			"cronWorkflow": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "cronworkflows",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"workflowTemplate": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "workflowtemplates",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"workflow": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "workflows",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"appProject": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "appprojects",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"application": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "applications",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"eventBus": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "eventbus",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"eventSource": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "eventsources",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"sensor": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "sensors",
				Namespace: runtimeName,
				Selectors: selectors,
			},
			"rollout": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "rollouts",
				Namespace: runtimeName,
				Selectors: selectors,
			},
		},
	})
	if err := insFs.WriteYamls(insFs.Join(resPath, "event-source.yaml"), eventSource); err != nil {
		return err
	}

	sensor := eventsutil.CreateSensor(&eventsutil.CreateSensorOptions{
		Name:            gsName + "-sensor",
		Namespace:       runtimeName,
		EventSourceName: eventSourceName,
		EventBusName:    store.Get().EventBusName,
		TriggerURL:      cfBaseURL + store.Get().EventReportingEndpoint,
		Triggers: []string{
			// "clusterWorkflowTemplate",
			"workflowTemplate",
			"workflow",
			"appProject",
			"application",
			"eventBus",
			"eventSource",
			"sensor",
			"rollout",
		},
	})
	if err = insFs.WriteYamls(insFs.Join(resPath, "sensor.yaml"), sensor); err != nil {
		return err
	}

	gsPath := gsCloneOpts.FS.Join(apstore.Default.AppsDir, gsName, runtimeName)
	fullGsPath := gsCloneOpts.FS.Join(gsCloneOpts.FS.Root(), gsPath)[1:]
	syncApp := cdutil.CreateApp(&cdutil.CreateAppOptions{
		Name:      gsSyncName,
		Namespace: runtimeName,
		Project:   runtimeName,
		SyncWave:  10,
		RepoURL:   gsCloneOpts.URL(),
		Revision:  gsCloneOpts.Revision(),
		SrcPath:   fullGsPath,
	})
	if err = insFs.WriteYamls(insFs.Join(resPath, gsName+"-synchronize.yaml"), syncApp); err != nil {
		return err
	}

	_, err = insRepo.Persist(ctx, &git.PushOptions{
		CommitMsg: fmt.Sprintf("Created %s Resources", gsName),
	})
	if err != nil {
		return err
	}

	appDef := &runtime.AppDef{
		Name: gsName,
		Type: application.AppTypeDirectory,
		URL:  insCloneOpts.URL() + insFs.Join(insFs.Root(), resPath),
	}
	if err = appDef.CreateApp(ctx, nil, insCloneOpts, runtimeName, store.Get().CFGitSourceType, nil); err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	return nil
}
