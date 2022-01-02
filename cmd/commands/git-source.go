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
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	ingressutil "github.com/codefresh-io/cli-v2/pkg/util/ingress"
	wfutil "github.com/codefresh-io/cli-v2/pkg/util/workflow"

	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	apicommon "github.com/argoproj/argo-events/pkg/apis/common"
	eventsourcereg "github.com/argoproj/argo-events/pkg/apis/eventsource"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorreg "github.com/argoproj/argo-events/pkg/apis/sensor"
	sensorsv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	wf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type (
	GitSourceCreateOptions struct {
		InsCloneOpts        *git.CloneOptions
		GsCloneOpts         *git.CloneOptions
		GsName              string
		RuntimeName         string
		CreateDemoResources bool
		Exclude             string
		Include             string
	}

	GitSourceDeleteOptions struct {
		RuntimeName  string
		GsName       string
		InsCloneOpts *git.CloneOptions
		Timeout      time.Duration
	}

	GitSourceEditOptions struct {
		RuntimeName  string
		GsName       string
		InsCloneOpts *git.CloneOptions
		GsCloneOpts  *git.CloneOptions
	}

	gitSourceCronExampleOptions struct {
		runtimeName string
		gsCloneOpts *git.CloneOptions
		gsFs        fs.FS
	}

	gitSourceGithubExampleOptions struct {
		runtimeName string
		gsCloneOpts *git.CloneOptions
		gsFs        fs.FS
	}
)

func NewGitSourceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "git-source",
		Short:             "Manage git-sources of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewGitSourceCreateCommand())
	cmd.AddCommand(NewGitSourceListCommand())
	cmd.AddCommand(NewGitSourceDeleteCommand())
	cmd.AddCommand(NewGitSourceEditCommand())

	return cmd
}

func NewGitSourceCreateCommand() *cobra.Command {
	var (
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
		createRepo   bool
	)

	cmd := &cobra.Command{
		Use:   "create runtime_name git-source_name",
		Short: "add a new git-source to an existing runtime",
		Example: util.Doc(`
			<BIN> git-source create runtime_name git-source-name --git-src-repo https://github.com/owner/repo-name/my-workflow
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store.Get().Silent = true

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name")
			}

			if gsCloneOpts.Repo == "" {
				log.G(ctx).Fatal("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name/path/to/workflow")
			}

			err := ensureRepo(cmd, args[0], insCloneOpts, true)
			if err != nil {
				return err
			}

			isValid, err := IsValidName(args[1])
			if err != nil {
				log.G(ctx).Fatal("failed to check the validity of the git-source name")
			}

			if !isValid {
				log.G(ctx).Fatal("git-source name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
			}

			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			if createRepo {
				gsCloneOpts.CreateIfNotExist = createRepo
			}

			insCloneOpts.Parse()
			gsCloneOpts.Parse()

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			return RunGitSourceCreate(ctx, &GitSourceCreateOptions{
				InsCloneOpts:        insCloneOpts,
				GsCloneOpts:         gsCloneOpts,
				GsName:              args[1],
				RuntimeName:         args[0],
				CreateDemoResources: false,
			})
		},
	}

	cmd.Flags().BoolVar(&createRepo, "create-repo", false, "If true, will create the specified git-source repo in case it doesn't already exist")

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{})
	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:   "git-src",
		Optional: true,
	})

	return cmd
}

func RunGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	// upsert git-source repo

	gsRepo, gsFs, err := opts.GsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone git-source repo: %w", err)
	}

	if opts.CreateDemoResources {
		if err := createDemoResources(ctx, opts, gsRepo, gsFs); err != nil {
			return fmt.Errorf("failed to create git source demo resources: %w", err)
		}
	}

	appDef := &runtime.AppDef{
		Name: opts.GsName,
		Type: application.AppTypeDirectory,
		URL:  opts.GsCloneOpts.Repo,
	}

	if err := appDef.CreateApp(ctx, nil, opts.InsCloneOpts, opts.RuntimeName, store.Get().CFGitSourceType, opts.Include, ""); err != nil {
		return fmt.Errorf("failed to create git-source application. Err: %w", err)
	}
	log.G(ctx).Infof("Successfully created git-source: '%s'", opts.GsName)

	return nil
}

func createDemoResources(ctx context.Context, opts *GitSourceCreateOptions, gsRepo git.Repository, gsFs fs.FS) error {
	fi, err := gsFs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read files in git-source repo. Err: %w", err)
	}

	if len(fi) == 0 {
		err = createCronExamplePipeline(&gitSourceCronExampleOptions{
			runtimeName: opts.RuntimeName,
			gsCloneOpts: opts.GsCloneOpts,
			gsFs:        gsFs,
		})
		if err != nil {
			return fmt.Errorf("failed to create cron example pipeline. Error: %w", err)
		}

		err = createGithubExamplePipeline(&gitSourceGithubExampleOptions{
			runtimeName: opts.RuntimeName,
			gsCloneOpts: opts.GsCloneOpts,
			gsFs:        gsFs,
		})
		if err != nil {
			return fmt.Errorf("failed to create github example pipeline. Error: %w", err)
		}

		commitMsg := fmt.Sprintf("Created demo pipelines in %s Directory", opts.GsCloneOpts.Path())

		log.G(ctx).Info("Pushing demo pipelines to the new git-source repo")
		if err := apu.PushWithMessage(ctx, gsRepo, commitMsg); err != nil {
			return fmt.Errorf("failed to push demo pipelines to git-source repo: %w", err)
		}
	}

	return nil
}

func createCronExamplePipeline(opts *gitSourceCronExampleOptions) error {
	err := createDemoWorkflowTemplate(opts.gsFs, opts.runtimeName)
	if err != nil {
		return fmt.Errorf("failed to create demo workflowTemplate: %w", err)
	}

	eventSourceFilePath := opts.gsFs.Join(opts.gsCloneOpts.Path(), store.Get().CronExampleEventSourceFileName)
	sensorFilePath := opts.gsFs.Join(opts.gsCloneOpts.Path(), store.Get().CronExampleSensorFileName)

	eventSource := createCronExampleEventSource()
	err = opts.gsCloneOpts.FS.WriteYamls(eventSourceFilePath, eventSource)
	if err != nil {
		return fmt.Errorf("failed to write yaml of eventsource. Error: %w", err)
	}

	trigger, err := createCronExampleTrigger()
	triggers := []sensorsv1alpha1.Trigger{*trigger}
	if err != nil {
		return fmt.Errorf("failed to create cron example trigger. Error: %w", err)
	}

	sensor, err := createCronExampleSensor(triggers, opts.runtimeName)
	if err != nil {
		return fmt.Errorf("failed to create cron example sensor. Error: %w", err)
	}

	err = opts.gsCloneOpts.FS.WriteYamls(sensorFilePath, sensor)
	if err != nil {
		return fmt.Errorf("failed to write yaml of cron example sensor. Error: %w", err)
	}

	return nil
}

func createCronExampleEventSource() *eventsourcev1alpha1.EventSource {
	return &eventsourcev1alpha1.EventSource{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventsourcereg.Kind,
			APIVersion: eventsourcereg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: store.Get().CronExampleEventSourceName,
		},
		Spec: eventsourcev1alpha1.EventSourceSpec{
			EventBusName: store.Get().EventBusName,
			Calendar: map[string]eventsourcev1alpha1.CalendarEventSource{
				store.Get().CronExampleEventName: {
					Interval: "5m",
				},
			},
		},
	}
}

func createCronExampleSensor(triggers []sensorsv1alpha1.Trigger, runtimeName string) (*sensorsv1alpha1.Sensor, error) {
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().CronExampleDependencyName,
			EventSourceName: store.Get().CronExampleEventSourceName,
			EventName:       store.Get().CronExampleEventName,
		},
	}

	return &sensorsv1alpha1.Sensor{
		TypeMeta: metav1.TypeMeta{
			Kind:       sensorreg.Kind,
			APIVersion: sensorreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cron",
		},
		Spec: sensorsv1alpha1.SensorSpec{
			EventBusName: "codefresh-eventbus",
			Template: &sensorsv1alpha1.Template{
				ServiceAccountName: "argo-server",
			},
			Dependencies: dependencies,
			Triggers:     triggers,
		},
	}, nil
}

func createCronExampleTrigger() (*sensorsv1alpha1.Trigger, error) {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          "cron-",
		SpecWfTemplateRefName: store.Get().CronExampleTriggerTemplateName,
		Parameters: []string{
			"message",
		},
	})

	workflowResource := apicommon.NewResource(workflow)

	return &sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().CronExampleTriggerTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				GroupVersionResource: metav1.GroupVersionResource{
					Group:    "argoproj.io",
					Version:  "v1alpha1",
					Resource: store.Get().WorkflowResourceName,
				},
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().CronExampleDependencyName,
							DataKey:        "eventTime",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
	}, nil
}

func NewGitSourceListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list runtime_name",
		Short:   "List all Codefresh git-sources of a given runtime",
		Example: util.Doc(`<BIN> git-source list my-runtime`),
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.G(cmd.Context()).Fatal("must enter runtime name")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			return RunGitSourceList(ctx, args[0])
		},
	}
	return cmd
}

func RunGitSourceList(ctx context.Context, runtimeName string) error {
	isRuntimeExists := checkExistingRuntimes(ctx, runtimeName)
	if isRuntimeExists == nil {
		return fmt.Errorf("there is no runtime by the name: %s", runtimeName)
	}

	gitSources, err := cfConfig.NewClient().V2().GitSource().List(ctx, runtimeName)
	if err != nil {
		return fmt.Errorf("failed to get git-sources list. Err: %w", err)
	}

	if len(gitSources) == 0 {
		log.G(ctx).WithField("runtime", runtimeName).Info("no git-sources were found in runtime")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tREPOURL\tPATH\tHEALTH-STATUS\tSYNC-STATUS")
	if err != nil {
		return fmt.Errorf("failed to print git-source list table headers. Err: %w", err)
	}

	for _, gs := range gitSources {
		name := gs.Metadata.Name
		repoURL := "N/A"
		path := "N/A"
		healthStatus := "N/A"
		syncStatus := gs.Self.Status.SyncStatus.String()

		if gs.Self.Status.HealthStatus != nil {
			healthStatus = gs.Self.Status.HealthStatus.String()
		}

		if gs.Self.RepoURL != nil {
			repoURL = *gs.Self.RepoURL
		}

		if gs.Self.Path != nil {
			path = *gs.Self.Path
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			name,
			repoURL,
			path,
			healthStatus,
			syncStatus,
		)

		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func NewGitSourceDeleteCommand() *cobra.Command {
	var (
		insCloneOpts *git.CloneOptions
	)

	cmd := &cobra.Command{
		Use:   "delete runtime_name git-source_name",
		Short: "delete a git-source from a runtime",
		Example: util.Doc(`
			<BIN> git-source delete runtime_name git-source_name 
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store.Get().Silent = true

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name")
			}

			err := ensureRepo(cmd, args[0], insCloneOpts, true)
			if err != nil {
				return err
			}

			insCloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			return RunGitSourceDelete(ctx, &GitSourceDeleteOptions{
				RuntimeName:  args[0],
				GsName:       args[1],
				Timeout:      aputil.MustParseDuration(cmd.Flag("request-timeout").Value.String()),
				InsCloneOpts: insCloneOpts,
			})
		},
	}

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{})

	return cmd
}

func RunGitSourceDelete(ctx context.Context, opts *GitSourceDeleteOptions) error {
	err := apcmd.RunAppDelete(ctx, &apcmd.AppDeleteOptions{
		CloneOpts:   opts.InsCloneOpts,
		ProjectName: opts.RuntimeName,
		AppName:     opts.GsName,
		Global:      false,
	})

	if err != nil {
		return fmt.Errorf("failed to delete the git-source %s. Err: %w", opts.GsName, err)
	}

	log.G(ctx).Infof("Successfully deleted the git-source: %s", opts.GsName)

	return nil
}

func NewGitSourceEditCommand() *cobra.Command {
	var (
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
	)

	cmd := &cobra.Command{
		Use:   "edit runtime_name git-source_name",
		Short: "edit a git-source of a runtime",
		Example: util.Doc(`
			<BIN> git-source edit runtime_name git-source_name --git-src-repo https://github.com/owner/repo-name/my-workflow
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store.Get().Silent = true

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter a runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter a git-source name")
			}

			if gsCloneOpts.Repo == "" {
				log.G(ctx).Fatal("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name/path/to/workflow")
			}

			err := ensureRepo(cmd, args[0], insCloneOpts, true)
			if err != nil {
				return err
			}

			insCloneOpts.Parse()
			gsCloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := verifyCLILatestVersion(ctx); err != nil {
				return err
			}

			return RunGitSourceEdit(ctx, &GitSourceEditOptions{
				RuntimeName:  args[0],
				GsName:       args[1],
				InsCloneOpts: insCloneOpts,
				GsCloneOpts:  gsCloneOpts,
			})
		},
	}

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
	})

	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
	})

	return cmd
}

func RunGitSourceEdit(ctx context.Context, opts *GitSourceEditOptions) error {
	repo, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone the installation repo, attemptint to edit git-source %s. Err: %w", opts.GsName, err)
	}

	c := &application.Config{}
	err = fs.ReadJson(fs.Join(apstore.Default.AppsDir, opts.GsName, opts.RuntimeName, "config.json"), c)
	if err != nil {
		return fmt.Errorf("failed to read the config.json of git-source: %s. Err: %w", opts.GsName, err)
	}

	c.SrcPath = opts.GsCloneOpts.Path()
	c.SrcRepoURL = opts.GsCloneOpts.URL()
	c.SrcTargetRevision = opts.GsCloneOpts.Revision()

	err = fs.WriteJson(fs.Join(apstore.Default.AppsDir, opts.GsName, opts.RuntimeName, "config.json"), c)
	if err != nil {
		return fmt.Errorf("failed to write the updated config.json of git-source: %s. Err: %w", opts.GsName, err)
	}

	log.G(ctx).Info("Pushing updated GitSource to the installation repo")
	if err := apu.PushWithMessage(ctx, repo, fmt.Sprintf("Persisted an updated git-source '%s'", opts.GsName)); err != nil {
		return fmt.Errorf("failed to persist the updated git-source: %s. Err: %w", opts.GsName, err)
	}

	return nil
}

func createDemoWorkflowTemplate(gsFs fs.FS, runtimeName string) error {
	wfTemplate := &wfv1alpha1.WorkflowTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       wf.WorkflowTemplateKind,
			APIVersion: wfv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: store.Get().CronExampleTriggerTemplateName,
		},
		Spec: wfv1alpha1.WorkflowTemplateSpec{
			WorkflowSpec: wfv1alpha1.WorkflowSpec{
				Arguments: wfv1alpha1.Arguments{
					Parameters: []wfv1alpha1.Parameter{{Name: "message"}},
				},
				Entrypoint:         "whalesay",
				ServiceAccountName: store.Get().CodefreshSA,
				PodGC: &wfv1alpha1.PodGC{
					Strategy: wfv1alpha1.PodGCOnWorkflowCompletion,
				},
				Templates: []wfv1alpha1.Template{
					{
						Name: "whalesay",
						Inputs: wfv1alpha1.Inputs{
							Parameters: []wfv1alpha1.Parameter{{Name: "message", Value: wfv1alpha1.AnyStringPtr("hello world")}},
							Artifacts:  wfv1alpha1.Artifacts{},
						},
						Container: &corev1.Container{
							Image:   "docker/whalesay:latest",
							Command: []string{"cowsay"},
							Args:    []string{"{{inputs.parameters.message}}"},
						},
					},
				},
			},
		},
	}

	return gsFs.WriteYamls(store.Get().CronExampleWfTemplateFileName, wfTemplate)
}

func createGithubExamplePipeline(opts *gitSourceGithubExampleOptions) error {
	// Create an ingress that will manage external access to the github eventsource service
	ingress := createGithubExampleIngress()
	ingressFilePath := opts.gsFs.Join(opts.gsCloneOpts.Path(), store.Get().GithubExampleIngressFileName)
	err := opts.gsCloneOpts.FS.WriteYamls(ingressFilePath, ingress)
	if err != nil {
		return fmt.Errorf("failed to write yaml of github example ingress. Error: %w", err)
	}

	// Create a github eventsource that will listen to push events in the git source repo
	gsRepoURL := opts.gsCloneOpts.URL()
	eventSource := createGithubExampleEventSource(gsRepoURL)
	eventSourceFilePath := opts.gsFs.Join(opts.gsCloneOpts.Path(), store.Get().GithubExampleEventSourceFileName)
	err = opts.gsCloneOpts.FS.WriteYamls(eventSourceFilePath, eventSource)
	if err != nil {
		return fmt.Errorf("failed to write yaml of secret. Error: %w", err)
	}

	// Create a sensor that will listen to the events published by the github eventsource, and trigger workflows
	sensor := createGithubExampleSensor()
	sensorFilePath := opts.gsFs.Join(opts.gsCloneOpts.Path(), store.Get().GithubExampleSensorFileName)
	err = opts.gsCloneOpts.FS.WriteYamls(sensorFilePath, sensor)
	if err != nil {
		return fmt.Errorf("failed to write yaml of github example sensor. Error: %w", err)
	}

	return nil
}

func createGithubExampleIngress() *netv1.Ingress {
	return ingressutil.CreateIngress(&ingressutil.CreateIngressOptions{
		Name: store.Get().GithubExampleIngressObjectName,
		Paths: []ingressutil.IngressPath{
			{
				Path:        store.Get().GithubExampleEventSourceEndpointPath,
				PathType:    netv1.PathTypeImplementationSpecific,
				ServiceName: store.Get().GithubExampleEventSourceObjectName + "-eventsource-svc",
				ServicePort: store.Get().GithubExampleEventSourceServicePort,
			},
		},
	})
}

func getRepoOwnerAndNameFromRepoURL(repoURL string) (owner string, name string) {
	_, repoRef, _, _, _, _, _ := aputil.ParseGitUrl(repoURL)
	splitRepoRef := strings.Split(repoRef, "/")
	owner = splitRepoRef[0]
	name = splitRepoRef[1]
	return owner, name
}

func createGithubExampleEventSource(repoURL string) *eventsourcev1alpha1.EventSource {
	repoOwner, repoName := getRepoOwnerAndNameFromRepoURL(repoURL)

	return &eventsourcev1alpha1.EventSource{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventsourcereg.Kind,
			APIVersion: eventsourcereg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: store.Get().GithubExampleEventSourceObjectName,
		},
		Spec: eventsourcev1alpha1.EventSourceSpec{
			EventBusName: store.Get().EventBusName,
			Service: &eventsourcev1alpha1.Service{
				Ports: []corev1.ServicePort{
					{
						Port:       store.Get().GithubExampleEventSourceServicePort,
						TargetPort: intstr.IntOrString{StrVal: store.Get().GithubExampleEventSourceTargetPort},
					},
				},
			},
			Github: map[string]eventsourcev1alpha1.GithubEventSource{
				store.Get().GithubExampleEventName: {
					Webhook: &eventsourcev1alpha1.WebhookContext{
						Endpoint: store.Get().GithubExampleEventSourceEndpointPath,
						URL:      "http://replace-with-real-public-url",
						Port:     store.Get().GithubExampleEventSourceTargetPort,
						Method:   "POST",
					},
					Repositories: []eventsourcev1alpha1.OwnedRepositories{
						{
							Owner: repoOwner,
							Names: []string{
								repoName,
							},
						},
					},
					Events: []string{
						"push",
					},
					APIToken: &corev1.SecretKeySelector{
						Key: store.Get().GithubAccessTokenSecretKey,
						LocalObjectReference: corev1.LocalObjectReference{
							Name: store.Get().GithubAccessTokenSecretObjectName,
						},
					},
					ContentType: "json",
					Active:      true,
					Insecure:    true,
				},
			},
		},
	}
}

func createGithubExampleTrigger() sensorsv1alpha1.Trigger {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          "github-",
		SpecWfTemplateRefName: store.Get().GithubExampleTriggerTemplateName,
		Parameters: []string{
			"message",
		},
	})

	workflowResource := apicommon.NewResource(workflow)

	return sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().CronExampleTriggerTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				GroupVersionResource: metav1.GroupVersionResource{
					Group:    "argoproj.io",
					Version:  "v1alpha1",
					Resource: store.Get().WorkflowResourceName,
				},
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().GithubExampleDependencyName,
							DataKey:        "body.ref",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
		RetryStrategy: &apicommon.Backoff{Steps: 3},
	}
}

func createGithubExampleSensor() *sensorsv1alpha1.Sensor {
	triggers := []sensorsv1alpha1.Trigger{
		createGithubExampleTrigger(),
	}
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().GithubExampleDependencyName,
			EventSourceName: store.Get().GithubExampleEventSourceObjectName,
			EventName:       store.Get().GithubExampleEventName,
		},
	}

	return &sensorsv1alpha1.Sensor{
		TypeMeta: metav1.TypeMeta{
			Kind:       sensorreg.Kind,
			APIVersion: sensorreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: store.Get().GithubExampleSensorObjectName,
		},
		Spec: sensorsv1alpha1.SensorSpec{
			EventBusName: store.Get().EventBusName,
			Template: &sensorsv1alpha1.Template{
				ServiceAccountName: store.Get().WorkflowTriggerServiceAccount,
			},
			Dependencies: dependencies,
			Triggers:     triggers,
		},
	}
}
