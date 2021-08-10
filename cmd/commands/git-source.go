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

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
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
	var err error

	gsPath := gsFs.Join(apstore.Default.AppsDir, gsName, runtimeName, "demo-wf-template.yaml")
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
	if err = gsFs.WriteYamls(gsPath, wfTemplate); err != nil {
		return err
	}

	return err
}
