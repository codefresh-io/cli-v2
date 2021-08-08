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
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/spf13/cobra"
)

type (
	GitSourceCreateOptions struct {
		GitSourceName string
		SourcePath    string
		RuntimeName   string
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
		gitSourceName string
		insCloneOpts  *git.CloneOptions
		gsCloneOpts   *git.CloneOptions
	)

	cmd := &cobra.Command{
		Use: "create runtime_name git-source_name", 
		Short: "add a new git-source to an existing runtime",
		Example: util.Doc(`
			<BIN> git-source create runtime_name git-source-name
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
			ctx := cmd.Context()

			if len(args) < 1 {
				log.G(ctx).Fatal("must enter runtime name") 
			}

			if len(args) < 2 {
				log.G(ctx).Fatal("must enter git-source name") 
			}
			gitSourceName = args[1]

			return createGitSource(ctx, insCloneOpts, gsCloneOpts, gitSourceName, args[0], cfConfig.GetCurrentContext().URL)
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

func createGitSource(ctx context.Context, insCloneOpts *git.CloneOptions, gsCloneOpts *git.CloneOptions, gsName, runtimeName, cfBaseURL string) error {
	gsPath := gsCloneOpts.FS.Join(apstore.Default.AppsDir, gsName, runtimeName)
	fullGsPath := gsCloneOpts.FS.Join(gsCloneOpts.FS.Root(), gsPath)[1:]

	appDef := &runtime.AppDef{
		Name: gsName,
		Type: application.AppTypeDirectory,
		URL:  gsCloneOpts.URL() + fullGsPath,
	}
	if err := appDef.CreateApp(ctx, nil, insCloneOpts, runtimeName, store.Get().CFGitSourceType, nil); err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	return nil
}
