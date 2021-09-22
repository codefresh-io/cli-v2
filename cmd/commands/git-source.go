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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	eventsutil "github.com/codefresh-io/cli-v2/pkg/util/events"
	"github.com/juju/ansiterm"

	sensorsv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	wf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	GitSourceCreateOptions struct {
		insCloneOpts        *git.CloneOptions
		gsCloneOpts         *git.CloneOptions
		gsName              string
		runtimeName         string
		fullGsPath          string
		sensorFileName      string
		eventSourceFileName string
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
	)

	cmd := &cobra.Command{
		Use:   "create runtime_name git-source_name",
		Short: "add a new git-source to an existing runtime",
		Example: util.Doc(`
			<BIN> git-source create runtime_name git-source-name --git-src-repo https://github.com/owner/repo-name/my-workflow
		`),
		PreRun: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name")
			}

			if gsCloneOpts.Repo == "" {
				log.G(ctx).Fatal("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name/path/to/workflow")
			}

			isValid, err := IsValid(args[1])
			if err != nil {
				log.G(ctx).Fatal("failed to check the validity of the git-source name")
			}

			if !isValid {
				log.G(ctx).Fatal("git-source name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
			}

			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			insCloneOpts.Parse()
			gsCloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunGitSourceCreate(ctx, &GitSourceCreateOptions{
				insCloneOpts: insCloneOpts,
				gsCloneOpts:  gsCloneOpts,
				gsName:       args[1],
				runtimeName:  args[0],
				fullGsPath:   gsCloneOpts.Path(),
			})
		},
	}

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

	return cmd
}

func RunGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	log.G(ctx).Infof("USING CF-DEV 2")

	gsRepo, gsFs, err := opts.gsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	fi, err := gsFs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read files in git-source repo. Err: %w", err)
	}

	if len(fi) == 0 {
		if err = createDemoWorkflowTemplate(gsFs, opts.runtimeName); err != nil {
			return fmt.Errorf("failed to create demo workflowTemplate: %w", err)
		}

		pOpts := &git.PushOptions{
			CommitMsg: fmt.Sprintf("Created demo workflow template in %s Directory", opts.gsCloneOpts.Path()),
		}

		eventSourceFilePath := gsFs.Join("resources", opts.eventSourceFileName)
		sensorFolderPath := gsFs.Join("resources")

		eventSource := eventsutil.CreateEventSource(&eventsutil.CreateEventSourceOptions{
			Name:         store.Get().CronExampleEventSourceName,
			Namespace:    opts.runtimeName,
			EventBusName: store.Get().EventBusName,
			Calender: map[string]eventsutil.CreateCalenderEventSourceOptions{
				store.Get().ExampleWithInterval: {
					Interval: "5m",
				},
			},
		})

		err = opts.gsCloneOpts.FS.WriteYamls(eventSourceFilePath, eventSource)
		if err != nil {
			return fmt.Errorf("failed to create eventsource: %w", err)
		}

		err = createSensor(opts.gsCloneOpts.FS, "cron", sensorFolderPath, opts.runtimeName, store.Get().CronExampleEventSourceName, store.Get().ExampleWithInterval, "data", opts.sensorFileName)
		if err != nil {
			return fmt.Errorf("failed to create sensor: %w", err)
		}

		_, err = gsRepo.Persist(ctx, pOpts)
		if err != nil {
			if errors.Is(err, transport.ErrRepositoryNotFound) {
				log.G(ctx).Warn("failed to persist git-source repo, trying again in 3 seconds...")
				time.Sleep(time.Second * 3)

				_, err = gsRepo.Persist(ctx, pOpts)
				if err != nil {
					return fmt.Errorf("failed to push changes. Err: %w", err)
				}
			} else {
				return fmt.Errorf("failed to push changes. Err: %w", err)
			}
		}
	}

	appDef := &runtime.AppDef{
		Name: opts.gsName,
		Type: application.AppTypeDirectory,
		URL:  opts.gsCloneOpts.Repo,
	}
	if err := appDef.CreateApp(ctx, nil, opts.insCloneOpts, opts.runtimeName, store.Get().CFGitSourceType); err != nil {
		return fmt.Errorf("failed to create git-source application. Err: %w", err)
	}

	log.G(ctx).Infof("Successfully created the git-source: '%s'", opts.gsName)

	return nil
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
			return RunGitSourceList(cmd.Context(), args[0])
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
		repoURL := gs.Self.RepoURL
		path := gs.Self.Path
		healthStatus := "N/A"
		syncStatus := gs.Self.Status.SyncStatus.String()

		if gs.Self.Status.HealthStatus != nil {
			healthStatus = gs.Self.Status.HealthStatus.String()
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
		PreRun: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name")
			}

			insCloneOpts.Parse()
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

	insCloneOpts = git.AddFlags(cmd, &git.AddFlagsOptions{
		FS: memfs.New(),
	})

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

	log.G(ctx).Debug("Successfully deleted the git-source: %s", opts.GsName)

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
		PreRun: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter a runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter a git-source name")
			}

			if gsCloneOpts.Repo == "" {
				log.G(ctx).Fatal("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name/path/to/workflow")
			}

			insCloneOpts.Parse()
			gsCloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunGitSourceEdit(ctx, &GitSourceEditOptions{
				RuntimeName:  args[0],
				GsName:       args[1],
				InsCloneOpts: insCloneOpts,
				GsCloneOpts:  gsCloneOpts,
			})
		},
	}

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

	_, err = repo.Persist(ctx, &git.PushOptions{
		CommitMsg: "Persisted an updated git-source",
	})

	if err != nil {
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
			Name: "hello-world",
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
							Parameters: []wfv1alpha1.Parameter{{Name: "message", Value: wfv1alpha1.AnyStringPtr("hello-world")}},
							Artifacts:  wfv1alpha1.Artifacts{},
						},
						Container: &v1.Container{
							Image:   "docker/whalesay",
							Command: []string{"cowsay"},
							Args:    []string{"{{inputs.parameters.message}}"},
						},
					},
				},
			},
		},
	}

	return gsFs.WriteYamls(store.Get().DemoPipelineWfTemplate, wfTemplate)
}
