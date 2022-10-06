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
	"fmt"
	"os"
	"strings"
	"time"

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	eventsutil "github.com/codefresh-io/cli-v2/pkg/util/events"
	routingutil "github.com/codefresh-io/cli-v2/pkg/util/routing"
	wfutil "github.com/codefresh-io/cli-v2/pkg/util/workflow"

	"github.com/Masterminds/semver/v3"
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
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	apmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model/app-proxy"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
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
		HostName            string
		SkipIngress         bool
		IngressHost         string
		IngressClass        string
		IngressController   routingutil.RoutingController
		AccessMode          platmodel.AccessMode
		GatewayName         string
		GatewayNamespace    string
		GitProvider         cfgit.Provider
		useGatewayAPI       bool
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
		Include      *string
		Exclude      *string
	}

	gitSourceCalendarDemoPipelineOptions struct {
		runtimeName string
		gsCloneOpts *git.CloneOptions
		gsFs        fs.FS
	}

	gitSourceGitDemoPipelineOptions struct {
		runtimeName       string
		gsCloneOpts       *git.CloneOptions
		gitProvider       cfgit.Provider
		gsFs              fs.FS
		hostName          string
		ingressHost       string
		skipIngress       bool
		ingressClass      string
		ingressController routingutil.RoutingController
		accessMode        platmodel.AccessMode
		gatewayName       string
		gatewayNamespace  string
		useGatewayAPI     bool
	}

	dirConfig struct {
		application.Config
		Exclude string `json:"exclude"`
		Include string `json:"include"`
	}
)

var appProxyGitSourceSupport = semver.MustParse("0.0.328")

func NewGitSourceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "git-source",
		Short:             "Manage git-sources of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
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
		gitProvider  cfgit.Provider
		createRepo   bool
		include      string
		exclude      string
	)

	cmd := &cobra.Command{
		Use:   "create RUNTIME_NAME GITSOURCE_NAME",
		Short: "Adds a new git-source to an existing runtime",
		Args:  cobra.MaximumNArgs(2),
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

			gitProvider, err = cfgit.GetProvider(cfgit.ProviderType(gsCloneOpts.Provider), gsCloneOpts.Repo)
			if err != nil {
				log.G(ctx).Fatal("failed to infer git provider for git-source")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunGitSourceCreate(ctx, &GitSourceCreateOptions{
				InsCloneOpts:        insCloneOpts,
				GsCloneOpts:         gsCloneOpts,
				GitProvider:         gitProvider,
				GsName:              args[1],
				RuntimeName:         args[0],
				CreateDemoResources: false,
				Include:             include,
				Exclude:             exclude,
			})
		},
	}

	cmd.Flags().BoolVar(&createRepo, "create-repo", false, "If true, will create the specified git-source repo in case it doesn't already exist")
	cmd.Flags().StringVar(&include, "include", "", "files to include. can be either filenames or a glob")
	cmd.Flags().StringVar(&exclude, "exclude", "", "files to exclude. can be either filenames or a glob")

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{CloneForWrite: true})
	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:   "git-src",
		Optional: true,
	})

	return cmd
}

func RunGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	version, err := getRuntimeVersion(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	if version.LessThan(appProxyGitSourceSupport) {
		log.G(ctx).Warnf("runtime \"%s\" is using a deprecated git-source api. Versions %s and up use the app-proxy for this command. You are using version: %s", opts.RuntimeName, appProxyGitSourceSupport, version.String())
		return legacyGitSourceCreate(ctx, opts)
	}

	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	appSpecifier := opts.GsCloneOpts.Repo
	isInternal := util.StringIndexOf(store.Get().CFInternalGitSources, opts.GsName) > -1

	err = appProxy.AppProxyGitSources().Create(ctx, &apmodel.CreateGitSourceInput{
		AppName:       opts.GsName,
		AppSpecifier:  appSpecifier,
		DestServer:    store.Get().InCluster,
		DestNamespace: opts.RuntimeName,
		IsInternal:    &isInternal,
		Include:       &opts.Include,
		Exclude:       &opts.Exclude,
	})

	if err != nil {
		log.G(ctx).Errorf("failed to create git-source: %s", err.Error())
		log.G(ctx).Info("attempting creation of git-source without using app-proxy")
		return legacyGitSourceCreate(ctx, opts)
	}

	log.G(ctx).Infof("Successfully created git-source: \"%s\"", opts.GsName)
	return nil
}

func ensureGitSourceDirectory(ctx context.Context, opts *GitSourceCreateOptions, gsRepo git.Repository, gsFs fs.FS) error {
	fi, err := gsFs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read files in git-source repo. Err: %w", err)
	}

	if len(fi) > 0 {
		return nil
	}

	if err = billyUtils.WriteFile(gsFs, "DUMMY", []byte{}, 0666); err != nil {
		return fmt.Errorf("failed to write the git-source placeholder file. Err: %w", err)
	}

	commitMsg := fmt.Sprintf("Created a placeholder file in %s Directory", opts.GsCloneOpts.Path())

	log.G(ctx).Info("Pushing placeholder file to the default-git-source repo")
	if err := apu.PushWithMessage(ctx, gsRepo, commitMsg); err != nil {
		return fmt.Errorf("failed to push placeholder file to git-source repo: %w", err)
	}

	return nil
}

func NewGitSourceListCommand() *cobra.Command {
	var includeInternal bool

	cmd := &cobra.Command{
		Use:     "list RUNTIME_NAME",
		Short:   "List all Codefresh git-sources of a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> git-source list my-runtime`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must enter runtime name")
			}

			return RunGitSourceList(cmd.Context(), args[0], includeInternal)
		},
	}

	cmd.Flags().BoolVar(&includeInternal, "include-internal", false, "If true, will include the Codefresh internal git-sources")

	return cmd
}

func RunGitSourceList(ctx context.Context, runtimeName string, includeInternal bool) error {
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
		nameWithoutRuntimePrefix := strings.TrimPrefix(name, fmt.Sprintf("%s-", runtimeName))
		if util.StringIndexOf(store.Get().CFInternalGitSources, nameWithoutRuntimePrefix) > -1 && !includeInternal {
			continue
		}

		if gs.Self == nil {
			prefixToOmit := runtimeName + "-"
			log.G(ctx).Errorf(`creation of git-source "%s" is still awaiting completion`, strings.TrimPrefix(name, prefixToOmit))
			continue
		}

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
		Use:   "delete RUNTIME_NAME GITSOURCE_NAME",
		Short: "delete a git-source from a runtime",
		Args:  cobra.MaximumNArgs(2),
		Example: util.Doc(`
			<BIN> git-source delete runtime_name git-source_name 
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			store.Get().Silent = true

			if len(args) < 1 {
				return fmt.Errorf("must enter runtime name")
			}

			if len(args) < 2 {
				return fmt.Errorf("must enter git-source name")
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

			return RunGitSourceDelete(ctx, &GitSourceDeleteOptions{
				RuntimeName:  args[0],
				GsName:       args[1],
				Timeout:      aputil.MustParseDuration(cmd.Flag("request-timeout").Value.String()),
				InsCloneOpts: insCloneOpts,
			})
		},
	}

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{CloneForWrite: true})

	return cmd
}

func RunGitSourceDelete(ctx context.Context, opts *GitSourceDeleteOptions) error {
	version, err := getRuntimeVersion(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	if version.LessThan(appProxyGitSourceSupport) {
		log.G(ctx).Warnf("runtime \"%s\" is using a depracated git-source api. Versions %s and up use the app-proxy for this command. You are using version: %s", opts.RuntimeName, appProxyGitSourceSupport, version.String())
		return legacyGitSourceDelete(ctx, opts)
	}

	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.AppProxyGitSources().Delete(ctx, opts.GsName)
	if err != nil {
		log.G(ctx).Errorf("failed to delete git-source: %s", err.Error())
		log.G(ctx).Info("attempting deletion of git-source without using app-proxy")
		err = apcmd.RunAppDelete(ctx, &apcmd.AppDeleteOptions{
			CloneOpts:   opts.InsCloneOpts,
			ProjectName: opts.RuntimeName,
			AppName:     opts.GsName,
			Global:      false,
		})

		if err != nil {
			return fmt.Errorf("failed to delete the git-source %s. Err: %w", opts.GsName, err)
		}
	}

	log.G(ctx).Infof("Successfully deleted the git-source: %s", opts.GsName)
	return nil
}

func NewGitSourceEditCommand() *cobra.Command {
	var (
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
		include      string
		exclude      string
	)

	cmd := &cobra.Command{
		Use:   "edit RUNTIME_NAME GITSOURCE_NAME",
		Short: "edit a git-source of a runtime",
		Args:  cobra.MaximumNArgs(2),
		Example: util.Doc(`
			<BIN> git-source edit runtime_name git-source_name --git-src-repo https://github.com/owner/repo-name.git/path/to/dir
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			store.Get().Silent = true

			if len(args) < 1 {
				return fmt.Errorf("must enter a runtime name")
			}

			if len(args) < 2 {
				return fmt.Errorf("must enter a git-source name")
			}

			if gsCloneOpts.Repo == "" {
				return fmt.Errorf("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name.git/path/to/dir")
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

			opts := &GitSourceEditOptions{
				RuntimeName:  args[0],
				GsName:       args[1],
				InsCloneOpts: insCloneOpts,
				GsCloneOpts:  gsCloneOpts,
			}
			if cmd.Flags().Changed("include") {
				opts.Include = &include
			}

			if cmd.Flags().Changed("exclude") {
				opts.Exclude = &exclude
			}

			return RunGitSourceEdit(ctx, opts)
		},
	}

	cmd.Flags().StringVar(&include, "include", "", "files to include. can be either filenames or a glob")
	cmd.Flags().StringVar(&exclude, "exclude", "", "files to exclude. can be either filenames or a glob")

	insCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: true,
		CloneForWrite:    true,
	})

	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
	})

	return cmd
}

func RunGitSourceEdit(ctx context.Context, opts *GitSourceEditOptions) error {
	version, err := getRuntimeVersion(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	if version.LessThan(appProxyGitSourceSupport) {
		log.G(ctx).Warnf("runtime \"%s\" is using a depracated git-source api. Versions %s and up use the app-proxy for this command. You are using version: %s", opts.RuntimeName, appProxyGitSourceSupport, version.String())
		return legacyGitSourceEdit(ctx, opts)
	}

	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.AppProxyGitSources().Edit(ctx, &apmodel.EditGitSourceInput{
		AppName:      opts.GsName,
		AppSpecifier: opts.GsCloneOpts.Repo,
		Include:      opts.Include,
		Exclude:      opts.Exclude,
	})

	if err != nil {
		log.G(ctx).Errorf("failed to edit git-source: %s", err.Error())
		log.G(ctx).Info("attempting edit of git-source without using app-proxy")
		return legacyGitSourceEdit(ctx, opts)
	}

	log.G(ctx).Infof("Successfully edited git-source: \"%s\"", opts.GsName)
	return nil
}

func createDemoResources(ctx context.Context, opts *GitSourceCreateOptions, gsRepo git.Repository, gsFs fs.FS) error {
	fi, err := gsFs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read files in git-source repo. Err: %w", err)
	}

	if len(fi) == 0 {
		wfTemplateFilePath := store.Get().DemoWorkflowTemplateFileName
		wfTemplate := createDemoWorkflowTemplate()
		if err := writeObjectToYaml(gsFs, wfTemplateFilePath, &wfTemplate, cleanUpFieldsWorkflowTemplate); err != nil {
			return fmt.Errorf("failed to write yaml of demo workflow template. Error: %w", err)
		}

		err = createDemoCalendarPipeline(&gitSourceCalendarDemoPipelineOptions{
			runtimeName: opts.RuntimeName,
			gsCloneOpts: opts.GsCloneOpts,
			gsFs:        gsFs,
		})
		if err != nil {
			return fmt.Errorf("failed to create calendar example pipeline. Error: %w", err)
		}

		if opts.AccessMode == platmodel.AccessModeIngress {
			err = createDemoGitPipeline(&gitSourceGitDemoPipelineOptions{
				runtimeName:       opts.RuntimeName,
				gsCloneOpts:       opts.GsCloneOpts,
				gitProvider:       opts.GitProvider,
				gsFs:              gsFs,
				hostName:          opts.HostName,
				skipIngress:       opts.SkipIngress,
				ingressHost:       opts.IngressHost,
				ingressClass:      opts.IngressClass,
				ingressController: opts.IngressController,
				accessMode:        opts.AccessMode,
				gatewayName:       opts.GatewayName,
				gatewayNamespace:  opts.GatewayNamespace,
				useGatewayAPI:     opts.useGatewayAPI,
			})
			if err != nil {
				return fmt.Errorf("failed to create github example pipeline. Error: %w", err)
			}
		}

		commitMsg := fmt.Sprintf("Created demo pipelines in %s Directory", opts.GsCloneOpts.Path())

		log.G(ctx).Info("Pushing demo pipelines to the new git-source repo")

		if err := apu.PushWithMessage(ctx, gsRepo, commitMsg); err != nil {
			return fmt.Errorf("failed to push demo pipelines to git-source repo: %w", err)
		}
	}

	return nil
}

func createDemoWorkflowTemplate() *wfv1alpha1.WorkflowTemplate {
	return &wfv1alpha1.WorkflowTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       wf.WorkflowTemplateKind,
			APIVersion: wfv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: store.Get().DemoWorkflowTemplateName,
		},
		Spec: wfv1alpha1.WorkflowSpec{
			Arguments: wfv1alpha1.Arguments{
				Parameters: []wfv1alpha1.Parameter{{Name: "message"}},
			},
			Entrypoint:         "echo",
			ServiceAccountName: store.Get().CodefreshSA,
			PodGC: &wfv1alpha1.PodGC{
				Strategy: wfv1alpha1.PodGCOnWorkflowCompletion,
			},
			Templates: []wfv1alpha1.Template{
				{
					Name: "echo",
					Inputs: wfv1alpha1.Inputs{
						Parameters: []wfv1alpha1.Parameter{{Name: "message", Value: wfv1alpha1.AnyStringPtr("hello world")}},
						Artifacts:  wfv1alpha1.Artifacts{},
					},
					Container: &corev1.Container{
						Image:   "alpine",
						Command: []string{"echo"},
						Args:    []string{"{{inputs.parameters.message}}"},
					},
				},
			},
		},
	}
}

func createDemoCalendarPipeline(opts *gitSourceCalendarDemoPipelineOptions) error {
	eventSourceFilePath := store.Get().DemoCalendarEventSourceFileName
	eventSource := createDemoCalendarEventSource()
	if err := writeObjectToYaml(opts.gsFs, eventSourceFilePath, &eventSource, cleanUpFieldsCalendarEventSource); err != nil {
		return fmt.Errorf("failed to write yaml of demo calendar eventsource. Error: %w", err)
	}

	sensorFilePath := store.Get().DemoCalendarSensorFileName
	sensor := createDemoCalendarSensor()
	if err := writeObjectToYaml(opts.gsFs, sensorFilePath, &sensor, cleanUpFieldsCalendarSensor); err != nil {
		return fmt.Errorf("failed to write yaml of demo calendar sensor. Error: %w", err)
	}

	return nil
}

func createDemoCalendarEventSource() *eventsourcev1alpha1.EventSource {
	name := store.Get().DemoCalendarEventSourceObjectName
	es := createDemoEventSource(name)

	es.Spec.Calendar = map[string]eventsourcev1alpha1.CalendarEventSource{
		store.Get().DemoCalendarEventName: {
			Interval: "30m",
		},
	}

	return es
}

func createDemoCalendarSensor() *sensorsv1alpha1.Sensor {
	name := store.Get().DemoCalendarSensorObjectName
	triggers := []sensorsv1alpha1.Trigger{
		createDemoCalendarTrigger(),
	}
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().DemoCalendarDependencyName,
			EventSourceName: store.Get().DemoCalendarEventSourceObjectName,
			EventName:       store.Get().DemoCalendarEventName,
		},
	}

	return createDemoSensor(name, triggers, dependencies)

}

func createDemoCalendarTrigger() sensorsv1alpha1.Trigger {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          "calendar-",
		SpecWfTemplateRefName: store.Get().DemoWorkflowTemplateName,
		Parameters: []string{
			"message",
		},
	})

	workflowResource := apicommon.NewResource(workflow)

	return sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().DemoWorkflowTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().DemoCalendarDependencyName,
							DataKey:        "eventTime",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
	}
}

func createDemoGitPipeline(opts *gitSourceGitDemoPipelineOptions) error {
	if !opts.skipIngress && opts.accessMode == platmodel.AccessModeIngress {
		// Create an ingress that will manage external access to the git eventsource service
		routeOpts := routingutil.CreateRouteOpts{
			RuntimeName:       opts.runtimeName,
			IngressClass:      opts.ingressClass,
			Hostname:          opts.hostName,
			IngressController: opts.ingressController,
			GatewayName:       opts.gatewayName,
			GatewayNamespace:  opts.gatewayNamespace,
		}
		routeName, route := routingutil.CreateDemoPipelinesRoute(&routeOpts, opts.useGatewayAPI)
		routeFilePath := fmt.Sprintf("%s.%s.yaml", store.Get().DemoPipelinesIngressObjectName, routeName)
		if err := writeObjectToYaml(opts.gsFs, routeFilePath, &route, cleanUpFieldsIngress); err != nil {
			return fmt.Errorf("failed to write yaml of demo pipeline ingress. Error: %w", err)
		}
	}

	gitProviderType := opts.gitProvider.Type()
	switch gitProviderType {
	case "github":
		return createDemoGithubPipeline(opts)
	case "gitlab":
		return createDemoGitlabPipeline(opts)
	case "bitbucket-server":
		return createDemoBitbucketServerPipeline(opts)
	case "bitbucket":
		return nil
	default:
		return fmt.Errorf("demo git pipeline is not yet supported for provider %s", gitProviderType)
	}
}

func createDemoGithubPipeline(opts *gitSourceGitDemoPipelineOptions) error {
	// Create a github eventsource that will listen to push events in the git source repo
	gsRepoURL := opts.gsCloneOpts.URL()
	eventSource := createDemoGithubEventSource(gsRepoURL, opts.ingressHost, opts.runtimeName, opts.gitProvider)
	eventSourceFilePath := store.Get().DemoGitEventSourceFileName
	if err := writeObjectToYaml(opts.gsFs, eventSourceFilePath, &eventSource, cleanUpFieldsGithubEventSource); err != nil {
		return fmt.Errorf("failed to write yaml of github example eventsource. Error: %w", err)
	}

	// Create a sensor that will listen to the events published by the github eventsource, and trigger workflows
	sensor := createDemoGithubSensor()
	sensorFilePath := store.Get().DemoGitSensorFileName
	if err := writeObjectToYaml(opts.gsFs, sensorFilePath, &sensor, cleanUpFieldsGithubSensor); err != nil {
		return fmt.Errorf("failed to write yaml of github example sensor. Error: %w", err)
	}

	return nil
}

func createDemoGitlabPipeline(opts *gitSourceGitDemoPipelineOptions) error {
	// Create a gitlab eventsource that will listen to push events in the git source repo
	gsRepoURL := opts.gsCloneOpts.URL()
	eventSource := createDemoGitlabEventSource(gsRepoURL, opts.ingressHost, opts.runtimeName, opts.gitProvider)
	eventSourceFilePath := store.Get().DemoGitEventSourceFileName
	if err := writeObjectToYaml(opts.gsFs, eventSourceFilePath, &eventSource, cleanUpFieldsGitlabEventSource); err != nil {
		return fmt.Errorf("failed to write yaml of gitlab example eventsource. Error: %w", err)
	}

	// Create a sensor that will listen to the events published by the gitlab eventsource, and trigger workflows
	sensor := createDemoGitlabSensor()
	sensorFilePath := store.Get().DemoGitSensorFileName
	if err := writeObjectToYaml(opts.gsFs, sensorFilePath, &sensor, cleanUpFieldsGitlabSensor); err != nil {
		return fmt.Errorf("failed to write yaml of gitlab example sensor. Error: %w", err)
	}

	return nil
}

func createDemoBitbucketServerPipeline(opts *gitSourceGitDemoPipelineOptions) error {
	// Create a bitbucket server eventsource that will listen to push events in the git source repo
	gsRepoURL := opts.gsCloneOpts.URL()
	eventSource := createDemoBitbucketServerEventSource(gsRepoURL, opts.ingressHost, opts.runtimeName, opts.gitProvider)
	eventSourceFilePath := store.Get().DemoGitEventSourceFileName
	if err := writeObjectToYaml(opts.gsFs, eventSourceFilePath, &eventSource, cleanUpFieldsBitbucketServerEventSource); err != nil {
		return fmt.Errorf("failed to write yaml of bitbucket server example eventsource. Error: %w", err)
	}

	// Create a sensor that will listen to the events published by the bitbucket server eventsource, and trigger workflows
	sensor := createDemoBitbucketServerSensor()
	sensorFilePath := store.Get().DemoGitSensorFileName
	if err := writeObjectToYaml(opts.gsFs, sensorFilePath, &sensor, cleanUpFieldsBitbucketServerSensor); err != nil {
		return fmt.Errorf("failed to write yaml of bitbucket server example sensor. Error: %w", err)
	}

	return nil
}

func createDemoGithubEventSource(repoURL string, ingressHost string, runtimeName string, gitProvider cfgit.Provider) *eventsourcev1alpha1.EventSource {
	name := store.Get().DemoGitEventSourceObjectName
	es := createDemoEventSource(name)

	es.Spec.Service = &eventsourcev1alpha1.Service{
		Ports: []corev1.ServicePort{
			{
				Port:       store.Get().DemoGitEventSourceServicePort,
				TargetPort: intstr.IntOrString{StrVal: store.Get().DemoGitEventSourceTargetPort},
			},
		},
	}
	es.Spec.Github = map[string]eventsourcev1alpha1.GithubEventSource{
		store.Get().DemoGitEventName: {
			Events: []string{
				"push",
			},
			Repositories: []eventsourcev1alpha1.OwnedRepositories{
				getGithubRepoFromGitURL(repoURL),
			},
			GithubBaseURL: fmt.Sprintf("%s/", gitProvider.BaseURL()), // github base URL must have a trailing slash
			Webhook: &eventsourcev1alpha1.WebhookContext{
				Endpoint: fmt.Sprintf("%s/%s", util.GenerateIngressPathForDemoGitEventSource(runtimeName), store.Get().DemoGitEventName),
				URL:      strings.Trim(ingressHost, "/"),
				Port:     store.Get().DemoGitEventSourceTargetPort,
				Method:   "POST",
			},
			APIToken: &corev1.SecretKeySelector{
				Key: store.Get().GitTokenSecretKey,
				LocalObjectReference: corev1.LocalObjectReference{
					Name: store.Get().GitTokenSecretObjectName,
				},
			},
			ContentType:        "json",
			Active:             true,
			Insecure:           true,
			DeleteHookOnFinish: true,
		},
	}

	return es
}

func createDemoGithubTrigger() sensorsv1alpha1.Trigger {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          store.Get().DemoGitTriggerTemplateName + "-",
		SpecWfTemplateRefName: store.Get().DemoWorkflowTemplateName,
		Parameters: []string{
			"message",
		},
	})
	workflowResource := apicommon.NewResource(workflow)

	return sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().DemoGitTriggerTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().DemoGitDependencyName,
							DataTemplate:   "{{ trimPrefix \"refs/heads/\" .Input.body.ref }}",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
		RetryStrategy: &apicommon.Backoff{Steps: 3},
	}
}

func createDemoGithubDataFilters() *sensorsv1alpha1.EventDependencyFilter {
	return &sensorsv1alpha1.EventDependencyFilter{
		Data: []sensorsv1alpha1.DataFilter{
			{
				Path: fmt.Sprintf("body.%s", store.Get().GithubEventTypeHeader),
				Value: []string{
					"push",
				},
				Type: sensorsv1alpha1.JSONTypeString,
			},
			{
				Path:     "body.ref",
				Template: "{{ (split \"/\" .Input)._1 }}",
				Value: []string{
					"heads",
				},
				Type: sensorsv1alpha1.JSONTypeString,
			},
		},
	}
}

func createDemoGithubSensor() *sensorsv1alpha1.Sensor {
	name := store.Get().DemoGitSensorObjectName
	triggers := []sensorsv1alpha1.Trigger{
		createDemoGithubTrigger(),
	}
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().DemoGitDependencyName,
			EventSourceName: store.Get().DemoGitEventSourceObjectName,
			EventName:       store.Get().DemoGitEventName,
			Filters:         createDemoGithubDataFilters(),
		},
	}

	return createDemoSensor(name, triggers, dependencies)
}

func createDemoBitbucketServerEventSource(repoURL string, ingressHost string, runtimeName string, gitProvider cfgit.Provider) *eventsourcev1alpha1.EventSource {
	name := store.Get().DemoGitEventSourceObjectName
	es := createDemoEventSource(name)

	es.Spec.Service = &eventsourcev1alpha1.Service{
		Ports: []corev1.ServicePort{
			{
				Port:       store.Get().DemoGitEventSourceServicePort,
				TargetPort: intstr.IntOrString{StrVal: store.Get().DemoGitEventSourceTargetPort},
			},
		},
	}
	es.Spec.BitbucketServer = map[string]eventsourcev1alpha1.BitbucketServerEventSource{
		store.Get().DemoGitEventName: {
			Events: []string{
				"repo:refs_changed",
			},
			Repositories: []eventsourcev1alpha1.BitbucketServerRepository{
				getBitbucketServerRepoFromGitURL(repoURL),
			},
			Webhook: &eventsourcev1alpha1.WebhookContext{
				Endpoint: fmt.Sprintf("%s/%s", util.GenerateIngressPathForDemoGitEventSource(runtimeName), store.Get().DemoGitEventName),
				URL:      strings.Trim(ingressHost, "/"),
				Port:     store.Get().DemoGitEventSourceTargetPort,
				Method:   "POST",
			},
			AccessToken: &corev1.SecretKeySelector{
				Key: store.Get().GitTokenSecretKey,
				LocalObjectReference: corev1.LocalObjectReference{
					Name: store.Get().GitTokenSecretObjectName,
				},
			},
			BitbucketServerBaseURL: fmt.Sprintf("%s/rest", gitProvider.BaseURL()),
			DeleteHookOnFinish:     true,
		},
	}

	return es
}

func createDemoBitbucketServerTrigger() sensorsv1alpha1.Trigger {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          store.Get().DemoGitTriggerTemplateName + "-",
		SpecWfTemplateRefName: store.Get().DemoWorkflowTemplateName,
		Parameters: []string{
			"message",
		},
	})
	workflowResource := apicommon.NewResource(workflow)

	return sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().DemoGitTriggerTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().DemoGitDependencyName,
							DataTemplate:   "{{ (first .Input.body.changes).ref.displayId }}",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
		RetryStrategy: &apicommon.Backoff{Steps: 3},
	}
}

func createDemoBitbucketServerDataFilters() *sensorsv1alpha1.EventDependencyFilter {
	return &sensorsv1alpha1.EventDependencyFilter{
		Data: []sensorsv1alpha1.DataFilter{
			{
				Path: "body.eventKey",
				Value: []string{
					"repo:refs_changed",
				},
				Type: sensorsv1alpha1.JSONTypeString,
			},
			{
				Path: "body.changes.0.ref.type",
				Value: []string{
					"BRANCH",
				},
				Type: sensorsv1alpha1.JSONTypeString,
			},
		},
	}
}

func createDemoBitbucketServerSensor() *sensorsv1alpha1.Sensor {
	name := store.Get().DemoGitSensorObjectName
	triggers := []sensorsv1alpha1.Trigger{
		createDemoBitbucketServerTrigger(),
	}
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().DemoGitDependencyName,
			EventSourceName: store.Get().DemoGitEventSourceObjectName,
			EventName:       store.Get().DemoGitEventName,
			Filters:         createDemoBitbucketServerDataFilters(),
		},
	}

	return createDemoSensor(name, triggers, dependencies)
}

func createDemoGitlabEventSource(repoURL string, ingressHost string, runtimeName string, gitProvider cfgit.Provider) *eventsourcev1alpha1.EventSource {
	name := store.Get().DemoGitEventSourceObjectName
	es := createDemoEventSource(name)

	es.Spec.Service = &eventsourcev1alpha1.Service{
		Ports: []corev1.ServicePort{
			{
				Port:       store.Get().DemoGitEventSourceServicePort,
				TargetPort: intstr.IntOrString{StrVal: store.Get().DemoGitEventSourceTargetPort},
			},
		},
	}
	es.Spec.Gitlab = map[string]eventsourcev1alpha1.GitlabEventSource{
		store.Get().DemoGitEventName: {
			Events: []string{
				"PushEvents",
			},
			Projects: []string{
				getGitlabProjectFromGitURL(repoURL),
			},
			Webhook: &eventsourcev1alpha1.WebhookContext{
				Endpoint: fmt.Sprintf("%s/%s", util.GenerateIngressPathForDemoGitEventSource(runtimeName), store.Get().DemoGitEventName),
				URL:      strings.Trim(ingressHost, "/"),
				Port:     store.Get().DemoGitEventSourceTargetPort,
				Method:   "POST",
			},
			AccessToken: &corev1.SecretKeySelector{
				Key: store.Get().GitTokenSecretKey,
				LocalObjectReference: corev1.LocalObjectReference{
					Name: store.Get().GitTokenSecretObjectName,
				},
			},
			EnableSSLVerification: true,
			GitlabBaseURL:         gitProvider.BaseURL(),
			DeleteHookOnFinish:    true,
		},
	}

	return es
}

func createDemoGitlabTrigger() sensorsv1alpha1.Trigger {
	workflow := wfutil.CreateWorkflow(&wfutil.CreateWorkflowOptions{
		GenerateName:          store.Get().DemoGitTriggerTemplateName + "-",
		SpecWfTemplateRefName: store.Get().DemoWorkflowTemplateName,
		Parameters: []string{
			"message",
		},
	})
	workflowResource := apicommon.NewResource(workflow)

	return sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Name: store.Get().DemoGitTriggerTemplateName,
			ArgoWorkflow: &sensorsv1alpha1.ArgoWorkflowTrigger{
				Operation: sensorsv1alpha1.Submit,
				Source: &sensorsv1alpha1.ArtifactLocation{
					Resource: &workflowResource,
				},
				Parameters: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: store.Get().DemoGitDependencyName,
							DataTemplate:   "{{ trimPrefix \"refs/heads/\" .Input.body.ref }}",
						},
						Dest: "spec.arguments.parameters.0.value",
					},
				},
			},
		},
		RetryStrategy: &apicommon.Backoff{Steps: 3},
	}
}

func createDemoGitlabDataFilters() *sensorsv1alpha1.EventDependencyFilter {
	return &sensorsv1alpha1.EventDependencyFilter{
		Data: []sensorsv1alpha1.DataFilter{
			{
				Path: fmt.Sprintf("headers.%s.0", store.Get().GitlabEventTypeHeader),
				Value: []string{
					"Push Hook",
				},
				Type: sensorsv1alpha1.JSONTypeString,
			},
		},
	}
}

func createDemoGitlabSensor() *sensorsv1alpha1.Sensor {
	name := store.Get().DemoGitSensorObjectName
	triggers := []sensorsv1alpha1.Trigger{
		createDemoGitlabTrigger(),
	}
	dependencies := []sensorsv1alpha1.EventDependency{
		{
			Name:            store.Get().DemoGitDependencyName,
			EventSourceName: store.Get().DemoGitEventSourceObjectName,
			EventName:       store.Get().DemoGitEventName,
			Filters:         createDemoGitlabDataFilters(),
		},
	}

	return createDemoSensor(name, triggers, dependencies)
}

func createDemoEventSource(name string) *eventsourcev1alpha1.EventSource {
	tpl := &eventsourcev1alpha1.Template{Container: &corev1.Container{}}

	if store.Get().SetDefaultResources {
		eventsutil.SetDefaultResourceRequirements(tpl.Container)
	}

	return &eventsourcev1alpha1.EventSource{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventsourcereg.Kind,
			APIVersion: eventsourcereg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: eventsourcev1alpha1.EventSourceSpec{
			EventBusName: store.Get().EventBusName,
			Template:     tpl,
		},
	}
}

func createDemoSensor(name string, triggers []sensorsv1alpha1.Trigger, dependencies []sensorsv1alpha1.EventDependency) *sensorsv1alpha1.Sensor {
	tpl := &sensorsv1alpha1.Template{
		Container:          &corev1.Container{},
		ServiceAccountName: store.Get().WorkflowTriggerServiceAccount,
	}

	if store.Get().SetDefaultResources {
		eventsutil.SetDefaultResourceRequirements(tpl.Container)
	}

	return &sensorsv1alpha1.Sensor{
		TypeMeta: metav1.TypeMeta{
			Kind:       sensorreg.Kind,
			APIVersion: sensorreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: sensorsv1alpha1.SensorSpec{
			EventBusName: store.Get().EventBusName,
			Template:     tpl,
			Dependencies: dependencies,
			Triggers:     triggers,
		},
	}
}

func getGithubRepoFromGitURL(gitURL string) eventsourcev1alpha1.OwnedRepositories {
	_, repoRef, _, _, _, _, _ := aputil.ParseGitUrl(gitURL)
	splitRepoRef := strings.Split(repoRef, "/")
	owner := splitRepoRef[0]
	name := splitRepoRef[1]

	return eventsourcev1alpha1.OwnedRepositories{
		Owner: owner,
		Names: []string{
			name,
		},
	}
}

func getGitlabProjectFromGitURL(gitURL string) string {
	_, project, _, _, _, _, _ := aputil.ParseGitUrl(gitURL)

	return project
}

func getBitbucketServerRepoFromGitURL(url string) eventsourcev1alpha1.BitbucketServerRepository {
	_, repoRef, _, _, _, _, _ := aputil.ParseGitUrl(url)
	splitRepoRef := strings.Split(repoRef, "/")
	// splitRepoRef[0] is "scm"
	projectKey := splitRepoRef[1]
	repoSlug := splitRepoRef[2]

	return eventsourcev1alpha1.BitbucketServerRepository{
		ProjectKey:     projectKey,
		RepositorySlug: repoSlug,
	}
}

func cleanUpFieldsIngress(resource *interface{}) (map[string]interface{}, error) {
	crd, err := util.StructToMap(resource)
	if err != nil {
		return nil, err
	}
	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsCalendarEventSource(eventSource **eventsourcev1alpha1.EventSource) (map[string]interface{}, error) {
	crd, err := util.StructToMap(eventSource)
	if err != nil {
		return nil, err
	}
	_, schedule := nestedMapLookup(crd, "spec", "calendar", "example-with-interval", "schedule")

	if schedule != nil {
		delete(schedule, "schedule")
	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsWorkflowTemplate(wfTemplate **wfv1alpha1.WorkflowTemplate) (map[string]interface{}, error) {
	crd, err := util.StructToMap(wfTemplate)
	if err != nil {
		return nil, err
	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsCalendarSensor(sensor **sensorsv1alpha1.Sensor) (map[string]interface{}, error) {
	crd, err := util.StructToMap(sensor)
	if err != nil {
		return nil, err
	}

	_, triggers := nestedMapLookup(crd, "spec", "triggers")
	if triggers != nil {
		for _, value := range triggers["triggers"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {

				_, resource := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "status")
				if resource != nil {
					delete(resource, "status")
				}
				_, metadata := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "metadata", "creationTimestamp")
				if metadata != nil {
					delete(metadata, "creationTimestamp")
				}
			}
		}

	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsBitbucketServerEventSource(eventSource **eventsourcev1alpha1.EventSource) (map[string]interface{}, error) {
	crd, err := util.StructToMap(eventSource)
	if err != nil {
		return nil, err
	}

	_, targetPort := nestedMapLookup(crd, "spec", "service", "ports")
	if targetPort != nil {
		for _, value := range targetPort["ports"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {
				_, targetPort := nestedMapLookup(rec, "targetPort")
				if targetPort != nil {
					delete(targetPort, "targetPort")
				}
			}
		}
	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsBitbucketServerSensor(sensor **sensorsv1alpha1.Sensor) (map[string]interface{}, error) {
	crd, err := util.StructToMap(sensor)
	if err != nil {
		return nil, err
	}

	//Delete redunded fields from sensor
	_, triggers := nestedMapLookup(crd, "spec", "triggers")
	if triggers != nil {
		for _, value := range triggers["triggers"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {
				_, resource := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "status")
				if resource != nil {
					delete(resource, "status")
				}
				_, metadata := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "metadata", "creationTimestamp")
				if metadata != nil {
					delete(metadata, "creationTimestamp")
				}
			}
		}

	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsGitlabEventSource(eventSource **eventsourcev1alpha1.EventSource) (map[string]interface{}, error) {
	crd, err := util.StructToMap(eventSource)
	if err != nil {
		return nil, err
	}

	_, targetPort := nestedMapLookup(crd, "spec", "service", "ports")
	if targetPort != nil {
		for _, value := range targetPort["ports"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {
				_, targetPort := nestedMapLookup(rec, "targetPort")
				if targetPort != nil {
					delete(targetPort, "targetPort")
				}
			}
		}
	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsGitlabSensor(sensor **sensorsv1alpha1.Sensor) (map[string]interface{}, error) {
	crd, err := util.StructToMap(sensor)
	if err != nil {
		return nil, err
	}

	//Delete redunded fields from sensor
	_, triggers := nestedMapLookup(crd, "spec", "triggers")
	if triggers != nil {
		for _, value := range triggers["triggers"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {
				_, resource := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "status")
				if resource != nil {
					delete(resource, "status")
				}
				_, metadata := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "metadata", "creationTimestamp")
				if metadata != nil {
					delete(metadata, "creationTimestamp")
				}
			}
		}

	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsGithubEventSource(eventSource **eventsourcev1alpha1.EventSource) (map[string]interface{}, error) {
	crd, err := util.StructToMap(eventSource)
	if err != nil {
		return nil, err
	}

	_, targetPort := nestedMapLookup(crd, "spec", "service", "ports")
	if targetPort != nil {
		for _, value := range targetPort["ports"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {
				_, targetPort := nestedMapLookup(rec, "targetPort")
				if targetPort != nil {
					delete(targetPort, "targetPort")
				}
			}
		}
	}

	_, githup := nestedMapLookup(crd, "spec", "github", store.Get().DemoGitEventName, "id")
	if githup != nil {
		delete(githup, "id")
		delete(githup, "owner")
		delete(githup, "repository")
	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func cleanUpFieldsGithubSensor(sensor **sensorsv1alpha1.Sensor) (map[string]interface{}, error) {
	crd, err := util.StructToMap(sensor)
	if err != nil {
		return nil, err
	}

	//Delete redunded fields from sensor
	_, triggers := nestedMapLookup(crd, "spec", "triggers")
	if triggers != nil {
		for _, value := range triggers["triggers"].([]interface{}) {
			if rec, ok := value.(map[string]interface{}); ok {

				_, resource := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "status")
				if resource != nil {
					delete(resource, "status")
				}
				_, metadata := nestedMapLookup(rec, "template", "argoWorkflow", "source", "resource", "metadata", "creationTimestamp")
				if metadata != nil {
					delete(metadata, "creationTimestamp")
				}
			}
		}

	}

	deleteCommonRedundantFields(crd)

	return crd, nil
}

func nestedMapLookup(m map[string]interface{}, ks ...string) (rval interface{}, mm map[string]interface{}) {
	var ok bool

	if len(ks) == 0 {
		return nil, nil
	}
	if rval, ok = m[ks[0]]; !ok {
		return nil, nil
	} else if len(ks) == 1 {
		return rval, m
	} else if m, ok = rval.(map[string]interface{}); !ok {
		return nil, nil
	} else {
		return nestedMapLookup(m, ks[1:]...)
	}
}

func deleteCommonRedundantFields(crd map[string]interface{}) {
	delete(crd, "status")
	metadata := crd["metadata"].(map[string]interface{})
	delete(metadata, "creationTimestamp")
}

func getRuntimeVersion(ctx context.Context, runtimeName string) (*semver.Version, error) {
	rt, err := getRuntime(ctx, runtimeName)
	if err != nil {
		return nil, err
	}

	if rt.RuntimeVersion == nil {
		return nil, fmt.Errorf("runtime \"%s\" has no version", runtimeName)
	}

	return semver.MustParse(*rt.RuntimeVersion), nil
}

func legacyGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	// upsert git-source repo
	gsRepo, gsFs, err := opts.GsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone git-source repo: %w", err)
	}

	if opts.CreateDemoResources {
		if err := createDemoResources(ctx, opts, gsRepo, gsFs); err != nil {
			return fmt.Errorf("failed to create git-source demo resources: %w", err)
		}
	} else {
		if err := ensureGitSourceDirectory(ctx, opts, gsRepo, gsFs); err != nil {
			return fmt.Errorf("failed to ensure git-source directory: %w", err)
		}
	}

	appDef := &runtime.AppDef{
		Name:    opts.GsName,
		Type:    application.AppTypeDirectory,
		URL:     opts.GsCloneOpts.Repo,
		Include: opts.Include,
		Exclude: opts.Exclude,
	}

	appDef.IsInternal = util.StringIndexOf(store.Get().CFInternalGitSources, appDef.Name) > -1

	if err := appDef.CreateApp(ctx, nil, opts.InsCloneOpts, opts.RuntimeName, store.Get().CFGitSourceType); err != nil {
		return fmt.Errorf("failed to create git-source application. Err: %w", err)
	}

	log.G(ctx).Infof("Successfully created git-source: \"%s\"", opts.GsName)
	return nil
}

func legacyGitSourceEdit(ctx context.Context, opts *GitSourceEditOptions) error {
	repo, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone the installation repo, attempting to edit git-source %s. Err: %w", opts.GsName, err)
	}

	c := &dirConfig{}
	fileName := fs.Join(apstore.Default.AppsDir, opts.GsName, opts.RuntimeName, "config_dir.json")
	err = fs.ReadJson(fileName, c)
	if err != nil {
		return fmt.Errorf("failed to read the %s of git-source: %s. Err: %w", fileName, opts.GsName, err)
	}

	c.Config.SrcPath = opts.GsCloneOpts.Path()
	c.Config.SrcRepoURL = opts.GsCloneOpts.URL()
	c.Config.SrcTargetRevision = opts.GsCloneOpts.Revision()

	if opts.Include != nil {
		c.Include = *opts.Include
	}

	if opts.Exclude != nil {
		c.Exclude = *opts.Exclude
	}

	err = fs.WriteJson(fileName, c)
	if err != nil {
		return fmt.Errorf("failed to write the updated %s of git-source: %s. Err: %w", fileName, opts.GsName, err)
	}

	log.G(ctx).Info("Pushing updated GitSource to the installation repo")
	if err := apu.PushWithMessage(ctx, repo, fmt.Sprintf("Persisted an updated git-source \"%s\"", opts.GsName)); err != nil {
		return fmt.Errorf("failed to persist the updated git-source: %s. Err: %w", opts.GsName, err)
	}

	log.G(ctx).Infof("Successfully edited git-source: \"%s\"", opts.GsName)
	return nil
}

func legacyGitSourceDelete(ctx context.Context, opts *GitSourceDeleteOptions) error {
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

func writeObjectToYaml[Object any](
	gsFs fs.FS,
	filePath string,
	object Object,
	cleanUpFunc func(Object) (map[string]interface{}, error),
) error {
	var finalObject interface{} = object
	cleanObject, err := cleanUpFunc(object)
	if err == nil {
		finalObject = cleanObject
	}

	return gsFs.WriteYamls(filePath, finalObject)
}
