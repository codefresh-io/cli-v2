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

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/juju/ansiterm"

	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	wf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	GitSourceCreateOptions struct {
		insCloneOpts *git.CloneOptions
		gsCloneOpts  *git.CloneOptions
		gsName       string
		runtimeName  string
		fullGsPath   string
	}
)

func NewGitSourceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git-source",
		Short: "Manage git-sources of Codefresh runtimes",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewGitSourceCreateCommand())
	cmd.AddCommand(NewGitSourceListCommand())

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
			<BIN> git-source create runtime_name git-source-name https://github.com/owner/repo-name/my-workflow
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

			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			insCloneOpts.Parse()
			gsCloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunCreateGitSource(ctx, &GitSourceCreateOptions{
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

func NewGitSourceListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list runtime_name",
		Short:   "List all Codefresh git-sources of a given runtime",
		Example: util.Doc(`<BIN> git-source list my-runtime`),
		RunE: func(_ *cobra.Command, args []string) error {
			return RunGitSourceList(args[0])
		},
	}
	return cmd
}

func RunGitSourceList(runtimeName string) error {
	gitSources, err := cfConfig.NewClient().GitSource().List(runtimeName)

	if err != nil { // TODO: might be a redundant check
		return fmt.Errorf("failed to get git-sources list. Err: %w", err)
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tSTATUS\tVERSION")
	if err != nil {
		return fmt.Errorf("failed to print git-source list table headers. Err: %w", err)
	}

	for _, gs := range gitSources {
		// name := gs.
		// repoURL := gs.repoURL
		// path := gs.path
		fmt.Println("%s", gs)

		name := "test1"
		repoURL := "testrep"
		path := "testpath"

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			name,
			repoURL,
			path,
		)

		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func RunCreateGitSource(ctx context.Context, opts *GitSourceCreateOptions) error {
	gsRepo, gsFs, err := opts.gsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}

	fi, err := gsFs.ReadDir(".")

	if err != nil {
		return fmt.Errorf("failed to read files in git-source repo. Err: %w", err)
	}

	if len(fi) == 0 {
		if err = createDemoWorkflowTemplate(gsFs, opts.gsName, opts.runtimeName); err != nil {
			return fmt.Errorf("failed to create demo workflowTemplate: %w", err)
		}

		_, err = gsRepo.Persist(ctx, &git.PushOptions{
			CommitMsg: fmt.Sprintf("Created demo workflow template in %s Directory", opts.gsCloneOpts.Path()),
		})

		if err != nil {
			return fmt.Errorf("failed to push changes. Err: %w", err)
		}
	}

	appDef := &runtime.AppDef{
		Name: opts.gsName,
		Type: application.AppTypeDirectory,
		URL:  opts.gsCloneOpts.Repo,
	}
	if err := appDef.CreateApp(ctx, nil, opts.insCloneOpts, opts.runtimeName, store.Get().CFGitSourceType, nil); err != nil {
		return fmt.Errorf("failed to create git-source application. Err: %w", err)
	}

	log.G(ctx).Infof("done creating a new git-source: '%s'", opts.gsName)

	return nil
}

func createDemoWorkflowTemplate(gsFs fs.FS, gsName, runtimeName string) error {
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

	return gsFs.WriteYamls("demo-wf-template.yaml", wfTemplate)
}
