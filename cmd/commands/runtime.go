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
	"io/ioutil"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	appset "github.com/argoproj-labs/applicationset/api/v1alpha1"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	apicommon "github.com/argoproj/argo-events/pkg/apis/common"
	eventsourcereg "github.com/argoproj/argo-events/pkg/apis/eventsource"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorreg "github.com/argoproj/argo-events/pkg/apis/sensor"
	sensorsv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type (
	RuntimeCreateOptions struct {
		RuntimeName string
		KubeContext string
		KubeFactory kube.Factory
		installRepo *apcmd.RepoCreateOptions
		// gitSrcRepo  *apcmd.RepoCreateOptions
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

	return cmd
}

func NewRuntimeCreateCommand() *cobra.Command {
	var (
		f           kube.Factory
		installRepo *apcmd.RepoCreateOptions
		//gitSrcRepo  *apcmd.RepoCreateOptions
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
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := &RuntimeCreateOptions{
				KubeContext: "",
				KubeFactory: f,
				installRepo: installRepo,
				// gitSrcRepo:  gitSrcRepo,
			}
			if len(args) < 1 {
				log.G().Fatal("must enter runtime name")
			}

			opts.RuntimeName = args[0]
			installRepo.Public = false
			return RunRuntimeCreate(cmd.Context(), opts)
		},
	}

	installRepo = apcmd.AddRepoCreateFlags(cmd, "install")
	// gitSrcRepo = apcmd.AddRepoCreateFlags(cmd, "git-src")
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeCreate(ctx context.Context, opts *RuntimeCreateOptions) error {
	installOpts, err := apcmd.RunRepoCreate(ctx, opts.installRepo)
	if err != nil {
		return err
	}

	installOpts.Progress = ioutil.Discard
	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: store.Get().ArgoCDManifestsURL,
		Namespace:    opts.RuntimeName,
		KubeContext:  opts.KubeContext,
		KubeFactory:  opts.KubeFactory,
		CloneOptions: installOpts,
	})
	if err != nil {
		return err
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   installOpts,
		ProjectName: opts.RuntimeName,
	})
	if err != nil {
		return err
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "events", store.Get().ArgoEventsManifestsURL, application.AppTypeKustomize, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application events: %w", err)
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "rollouts", store.Get().ArgoRolloutsManifestsURL, application.AppTypeKustomize, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application rollouts: %w", err)
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "workflows", store.Get().ArgoWorkflowsManifestsURL, application.AppTypeKustomize, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application workflows: %w", err)
	}

	if err = createCodefreshResources(ctx, installOpts, opts); err != nil {
		return fmt.Errorf("failed to update project file: %w", err)
	}

	return nil
}

func createCodefreshResources(ctx context.Context, cloneOpts *git.CloneOptions, opts *RuntimeCreateOptions) error {
	tokenSecret, err := getTokenSecret(opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, tokenSecret); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	resPath := cloneOpts.FS.Join(apstore.Default.AppsDir, store.Get().ComponentsReporterName, opts.RuntimeName, "resources")
	if err := createApp(ctx, cloneOpts, opts.RuntimeName, store.Get().ComponentsReporterName, cloneOpts.URL()+"/"+resPath, application.AppTypeDirectory, opts.RuntimeName); err != nil {
		return err
	}

	r, repofs, err := cloneOpts.Clone(ctx)
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

	if err := createSensor(repofs, resPath, opts.RuntimeName); err != nil {
		return err
	}

	return r.Persist(ctx, &git.PushOptions{
		CommitMsg: "Created Codefresh Resources",
	})
}

func createApp(ctx context.Context, cloneOpts *git.CloneOptions, projectName, appName, appURL, appType, namespace string) error {
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

	appset.Spec.Template.Labels[store.Get().CFComponentKey] = "{{ appName }}"
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

func createEventSource(repofs fs.FS, path, runtimeName string) error {
	eventSource := &eventsourcev1alpha1.EventSource{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventsourcereg.Kind,
			APIVersion: eventsourcereg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ComponentsReporterName,
			Namespace: runtimeName,
		},
		Spec: eventsourcev1alpha1.EventSourceSpec{
			Template: &eventsourcev1alpha1.Template{
				ServiceAccountName: store.Get().ComponentsReporterSA,
			},
			Service: &eventsourcev1alpha1.Service{
				Ports: []v1.ServicePort{
					{
						Port:       int32(12000),
						TargetPort: intstr.FromInt(12000),
					},
				},
			},
			EventBusName: store.Get().EventBusName,
			Resource: map[string]eventsourcev1alpha1.ResourceEventSource{
				"components": {
					EventTypes: []eventsourcev1alpha1.ResourceEventType{
						eventsourcev1alpha1.ADD,
						eventsourcev1alpha1.UPDATE,
						eventsourcev1alpha1.DELETE,
					},
					GroupVersionResource: metav1.GroupVersionResource{
						Group:    "argoproj.io",
						Version:  "v1alpha1",
						Resource: "applications",
					},
					Namespace: runtimeName,
					Filter: &eventsourcev1alpha1.ResourceFilter{
						AfterStart: false,
						Labels: []eventsourcev1alpha1.Selector{
							{
								Key:       store.Get().CFComponentKey,
								Operation: "!=",
								Value:     "",
							},
						},
					},
				},
				"runtime": {
					EventTypes: []eventsourcev1alpha1.ResourceEventType{
						eventsourcev1alpha1.ADD,
						eventsourcev1alpha1.UPDATE,
						eventsourcev1alpha1.DELETE,
					},
					GroupVersionResource: metav1.GroupVersionResource{
						Group:    "argoproj.io",
						Version:  "v1alpha1",
						Resource: "applicationsets",
					},
					Namespace: runtimeName,
					Filter: &eventsourcev1alpha1.ResourceFilter{
						AfterStart: true,
						Labels: []eventsourcev1alpha1.Selector{
							{
								Key:       store.Get().CFComponentKey,
								Operation: "!=",
								Value:     "",
							},
						},
					},
				},
			},
		},
	}

	return repofs.WriteYamls(repofs.Join(path, "event-source.yaml"), eventSource)
}

func createSensor(repofs fs.FS, path, namespace string) error {
	sensor := &sensorsv1alpha1.Sensor{
		TypeMeta: metav1.TypeMeta{
			Kind:       sensorreg.Kind,
			APIVersion: sensorreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().ComponentsReporterName,
			Namespace: namespace,
		},
		Spec: sensorsv1alpha1.SensorSpec{
			EventBusName: store.Get().EventBusName,
			Dependencies: []sensorsv1alpha1.EventDependency{
				{
					Name:            "components",
					EventSourceName: store.Get().ComponentsReporterName,
					EventName:       "components",
				},
				{
					Name:            "runtime",
					EventSourceName: store.Get().ComponentsReporterName,
					EventName:       "runtime",
				},
			},
			Triggers: []sensorsv1alpha1.Trigger{
				{
					Template: &sensorsv1alpha1.TriggerTemplate{
						Conditions: "components",
						Name:       "http-trigger",
						HTTP: &sensorsv1alpha1.HTTPTrigger{
							URL:    cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "application/json",
							},
							SecureHeaders: []*apicommon.SecureHeader{
								{
									Name: "Autorization",
									ValueFrom: &apicommon.ValueFromSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: store.Get().CFTokenSecret,
											},
											Key: store.Get().CFTokenSecretKey,
										},
									},
								},
							},
							Payload: []sensorsv1alpha1.TriggerParameter{
								{
									Src: &sensorsv1alpha1.TriggerParameterSource{
										DependencyName: "components",
										DataKey:        "body",
									},
									Dest: "data",
								},
							},
						},
					},
					RetryStrategy: &apicommon.Backoff{
						Steps: 3,
						Duration: &apicommon.Int64OrString{
							StrVal: "3s",
						},
					},
				},
				{
					Template: &sensorsv1alpha1.TriggerTemplate{
						Conditions: "runtime",
						Name:       "http-trigger",
						HTTP: &sensorsv1alpha1.HTTPTrigger{
							URL:    cfConfig.GetCurrentContext().URL + store.Get().EventReportingEndpoint,
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "application/json",
							},
							SecureHeaders: []*apicommon.SecureHeader{
								{
									Name: "Autorization",
									ValueFrom: &apicommon.ValueFromSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: store.Get().CFTokenSecret,
											},
											Key: store.Get().CFTokenSecretKey,
										},
									},
								},
							},
							Payload: []sensorsv1alpha1.TriggerParameter{
								{
									Src: &sensorsv1alpha1.TriggerParameterSource{
										DependencyName: "runtime",
										DataKey:        "body",
									},
									Dest: "data",
								},
							},
						},
					},
					RetryStrategy: &apicommon.Backoff{
						Steps: 3,
						Duration: &apicommon.Int64OrString{
							StrVal: "3s",
						},
					},
				},
			},
		},
	}

	return repofs.WriteYamls(repofs.Join(path, "sensor.yaml"), sensor)
}
