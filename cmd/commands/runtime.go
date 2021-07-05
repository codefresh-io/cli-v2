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

	"github.com/codefresh-io/cli-v2/pkg/cdUtils"
	"github.com/codefresh-io/cli-v2/pkg/eventUtils"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/juju/ansiterm"

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
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	RuntimeCreateOptions struct {
		RuntimeName  string
		KubeContext  string
		KubeFactory  kube.Factory
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
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

	cmd.AddCommand(NewRuntimeCreateCommand())
	cmd.AddCommand(NewRuntimeListCommand())

	return cmd
}

func NewRuntimeCreateCommand() *cobra.Command {
	var (
		f            kube.Factory
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
	)

	cmd := &cobra.Command{
		Use:   "create [runtime_name]",
		Short: "Create a new Codefresh runtime",
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export INSTALL_GIT_TOKEN=<token>

# or with the flag:

		--install-git-token <token>

# Adds a new runtime

	<BIN> runtime create runtime-name --install-owner owner --install-name gitops_repo
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
			if len(args) < 1 {
				log.G().Fatal("must enter runtime name")
			}

			return RunRuntimeCreate(cmd.Context(), &RuntimeCreateOptions{
				RuntimeName:  args[0],
				KubeContext:  "",
				KubeFactory:  f,
				insCloneOpts: insCloneOpts,
				gsCloneOpts:  gsCloneOpts,
			})
		},
	}

	insCloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		Prefix:           "install",
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

func RunRuntimeCreate(ctx context.Context, opts *RuntimeCreateOptions) error {
	err := apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: store.Get().ArgoCDManifestsURL,
		Namespace:    opts.RuntimeName,
		KubeContext:  opts.KubeContext,
		KubeFactory:  opts.KubeFactory,
		CloneOptions: opts.insCloneOpts,
	})
	if err != nil {
		return err
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   opts.insCloneOpts,
		ProjectName: opts.RuntimeName,
	})
	if err != nil {
		return err
	}

	if err = createApp(ctx, opts.KubeFactory, opts.insCloneOpts, opts.RuntimeName, "rollouts", store.Get().ArgoRolloutsManifestsURL, application.AppTypeKustomize, opts.RuntimeName, false); err != nil {
		return fmt.Errorf("failed to create rollouts application: %w", err)
	}

	if err = createApp(ctx, opts.KubeFactory, opts.insCloneOpts, opts.RuntimeName, "workflows", store.Get().ArgoWorkflowsManifestsURL, application.AppTypeKustomize, opts.RuntimeName, false); err != nil {
		return fmt.Errorf("failed to create workflows application: %w", err)
	}

	if err = createApp(ctx, opts.KubeFactory, opts.insCloneOpts, opts.RuntimeName, "events", store.Get().ArgoEventsManifestsURL, application.AppTypeKustomize, opts.RuntimeName, true); err != nil {
		return fmt.Errorf("failed to create events application: %w", err)
	}

	if err = createComponentsReporter(ctx, opts.insCloneOpts, opts); err != nil {
		return fmt.Errorf("failed to create components-reporter: %w", err)
	}

	if err = createDemoWorkflowTemplate(ctx, opts.gsCloneOpts, store.Get().GitSourceName, opts.RuntimeName); err != nil {
		return err
	}

	if err = createGitSource(ctx, opts.insCloneOpts, opts.gsCloneOpts, store.Get().GitSourceName, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create `%s`: %w", store.Get().GitSourceName, err)
	}

	return nil
}

func NewRuntimeListCommand() *cobra.Command {
	

	cmd := &cobra.Command{
		Use:   "list ",
		Short: "List all Codefresh runtimes",
		Example: util.Doc(`<BIN> runtime list`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return listRuntimes(cmd.Context())
		},
	}
	return cmd
}

func listRuntimes(ctx context.Context) error {
	runtimes, err := cfConfig.NewClient().ArgoRuntime().List()
	if err != nil {
		return err
	}
	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tSTATUS\tVERSION")
	for _, rt := range runtimes {
		status := "N/A"
		namespace:= "N/A"
		name := "N/A"
		cluster := "N/A"
		version := "N/A"
		if rt.Status != nil {
			status = rt.Status.String()
		}
		if rt.Namespace != nil {
			namespace = *rt.Namespace
		}
		if rt.ObjectMeta != nil  && rt.ObjectMeta.Name != nil {
			name = *rt.ObjectMeta.Name
		}
		if rt.Cluster != nil {
			cluster = *rt.Cluster
		}
		if rt.Version != nil {
			version = *rt.Version
		}
		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
				name,
				namespace,
				cluster,
				status,
				version,
			)
	}
	return tb.Flush()

}

func createApp(ctx context.Context, f kube.Factory, cloneOpts *git.CloneOptions, projectName, appName, appURL, appType, namespace string, wait bool) error {
	timeout := time.Duration(0)
	if wait {
		timeout = store.Get().WaitTimeout
	}

	return apcmd.RunAppCreate(ctx, &apcmd.AppCreateOptions{
		CloneOpts:     cloneOpts,
		AppsCloneOpts: &git.CloneOptions{},
		ProjectName:   projectName,
		AppOpts: &application.CreateOptions{
			AppName:       appName,
			AppSpecifier:  appURL,
			AppType:       appType,
			DestNamespace: namespace,
		},
		KubeFactory: f,
		Timeout:     timeout,
	})
}

func createComponentsReporter(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeCreateOptions) error {
	tokenSecret, err := getTokenSecret(opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, tokenSecret); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().ComponentsReporterName, opts.RuntimeName, "resources")
	if err := createApp(ctx, opts.KubeFactory, cloneOpts, opts.RuntimeName, store.Get().ComponentsReporterName, cloneOpts.URL()+"/"+resPath, application.AppTypeDirectory, opts.RuntimeName, false); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	if err := updateProject(repofs, opts.RuntimeName); err != nil {
		return err
	}

	if err := createRBAC(repofs, resPath, opts.RuntimeName); err != nil {
		return err
	}

	if err := createEventSource(repofs, resPath, opts.RuntimeName); err != nil {
		return err
	}

	if err := createSensor(repofs, store.Get().ComponentsReporterName, resPath, opts.RuntimeName, store.Get().ComponentsReporterName); err != nil {
		return err
	}

	return r.Persist(ctx, &git.PushOptions{
		CommitMsg: "Created Codefresh Resources",
	})
}

func updateProject(repofs fs.FS, runtimeName string) error {
	projPath := repofs.Join(apstore.Default.ProjectsDir, runtimeName+".yaml")
	project, appset, err := getProjectInfoFromFile(repofs, projPath)
	if err != nil {
		return err
	}

	if appset.Spec.Template.Labels == nil {
		appset.Spec.Template.Labels = make(map[string]string)
	}
	if appset.Labels == nil {
		appset.Labels = make(map[string]string)
	}

	if project.ObjectMeta.Labels == nil {
		project.ObjectMeta.Labels = make(map[string]string)
	}

	appset.Spec.Template.Labels[store.Get().CFType] = "component"
	project.ObjectMeta.Labels[store.Get().CFType] = "runtime"
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

func getTokenSecret(namespace string) ([]byte, error) {
	token := cfConfig.GetCurrentContext().Token
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

func createRBAC(repofs fs.FS, path, runtimeName string) error {
	serviceAccount := &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ComponentsReporterSA,
			Namespace: runtimeName,
		},
	}

	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ComponentsReporterName,
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
			Name:      store.Get().ComponentsReporterName,
			Namespace: runtimeName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: runtimeName,
				Name:      store.Get().ComponentsReporterSA,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: store.Get().ComponentsReporterName,
		},
	}

	return repofs.WriteYamls(repofs.Join(path, "rbac.yaml"), serviceAccount, role, roleBinding)
}

func createEventSource(repofs fs.FS, path, namespace string) error {
	eventSource := eventUtils.CreateEventSource(&eventUtils.CreateEventSourceOptions{
		Name:               store.Get().ComponentsReporterName,
		Namespace:          namespace,
		ServiceAccountName: store.Get().ComponentsReporterSA,
		EventBusName:       store.Get().EventBusName,
		Resource: map[string]eventUtils.CreateResourceEventSourceOptions{
			"components": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "applications",
				Namespace: namespace,
				Selectors: []eventUtils.CreateSelectorOptions{
					{
						Key:       store.Get().CFType,
						Operation: "==",
						Value:     store.Get().CFComponentType,
					},
				},
			},
			"runtime": {
				Group:     "argoproj.io",
				Version:   "v1alpha1",
				Resource:  "appprojects",
				Namespace: namespace,
				Selectors: []eventUtils.CreateSelectorOptions{
					{
						Key:       store.Get().CFType,
						Operation: "==",
						Value:     store.Get().CFRuntimeType,
					},
				},
			},
		},
	})
	return repofs.WriteYamls(repofs.Join(path, "event-source.yaml"), eventSource)
}

func createSensor(repofs fs.FS, name, path, namespace, eventSourceName string) error {
	sensor := eventUtils.CreateSensor(&eventUtils.CreateSensorOptions{
		Name:            name,
		Namespace:       namespace,
		EventSourceName: eventSourceName,
		EventBusName:    store.Get().EventBusName,
		TriggerURL:      cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
		Triggers: []string{
			"components",
			"runtime",
		},
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

	return gsRepo.Persist(ctx, &git.PushOptions{
		CommitMsg: fmt.Sprintf("Created %s Directory", gsPath),
	})
}

func createGitSource(ctx context.Context, insCloneOpts *git.CloneOptions, gsCloneOpts *git.CloneOptions, gsName, runtimeName string) error {
	var err error

	insRepo, insFs, err := insCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	resPath := insFs.Join(apstore.Default.AppsDir, gsName, runtimeName, "resources")
	eventSourceName := gsName + "-event-source"
	gsSyncName := gsName + "-synchronize"
	selectors := []eventUtils.CreateSelectorOptions{
		{
			Key:       "app.kubernetes.io/instance",
			Operation: "==",
			Value:     gsSyncName,
		},
	}
	eventSource := eventUtils.CreateEventSource(&eventUtils.CreateEventSourceOptions{
		Name:               eventSourceName,
		Namespace:          runtimeName,
		ServiceAccountName: store.Get().ComponentsReporterSA,
		EventBusName:       store.Get().EventBusName,
		Resource: map[string]eventUtils.CreateResourceEventSourceOptions{
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

	sensor := eventUtils.CreateSensor(&eventUtils.CreateSensorOptions{
		Name:            gsName + "-sensor",
		Namespace:       runtimeName,
		EventSourceName: eventSourceName,
		EventBusName:    store.Get().EventBusName,
		TriggerURL:      cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
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
	syncApp := cdUtils.CreateApp(&cdUtils.CreateAppOptions{
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

	err = insRepo.Persist(ctx, &git.PushOptions{
		CommitMsg: fmt.Sprintf("Created %s Resources", gsName),
	})
	if err != nil {
		return err
	}

	fullResPath := insFs.Join(insFs.Root(), resPath)
	if err = createApp(ctx, nil, insCloneOpts, runtimeName, gsName, insCloneOpts.URL()+fullResPath, application.AppTypeDirectory, runtimeName, false); err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	return nil
}
