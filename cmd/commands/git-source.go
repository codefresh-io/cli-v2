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

	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/spf13/cobra"
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
		Use:   "create runtime_name git-source_name git-src-repo_full_path",
		Short: "add a new git-source to an existing runtime",
		Example: util.Doc(`
			<BIN> git-source create runtime_name git-source-name https://github.com/user/repo-name/my-workflow
		`),
		PreRun: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name")
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name")
			}

			if len(args) < 3 {
				log.G(ctx).Fatal("must enter the full path of the new git-source repo. Example: https://github.com/user/repo-name/my-workflow")
			}

			if gsCloneOpts.Auth.Password == "" {
				gsCloneOpts.Auth.Password = insCloneOpts.Auth.Password
			}

			insCloneOpts.Parse()
			
			gsCloneOpts.Repo = args[2]
			gsCloneOpts.Parse()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			
			return createGitSource(ctx, insCloneOpts, gsCloneOpts, args[1], args[0], cfConfig.GetCurrentContext().URL, gsCloneOpts.Path())
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

func createGitSource(ctx context.Context, insCloneOpts *git.CloneOptions, gsCloneOpts *git.CloneOptions, gsName, runtimeName, cfBaseURL, fullGsPath string) error {
	appDef := &runtime.AppDef{
		Name: gsName,
		Type: application.AppTypeDirectory,
		URL:  gsCloneOpts.URL() + fullGsPath,
	}
	if err := appDef.CreateApp(ctx, nil, insCloneOpts, runtimeName, store.Get().CFGitSourceType, nil); err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	log.G(ctx).Infof("done installing git-source '%s'", gsName)

	return nil
}
