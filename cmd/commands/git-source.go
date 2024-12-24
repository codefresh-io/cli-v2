// Copyright 2025 The Codefresh Authors.
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

	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/store"
	"github.com/codefresh-io/cli-v2/internal/util"

	apmodel "github.com/codefresh-io/go-sdk/pkg/model/app-proxy"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type (
	GitSourceCreateOptions struct {
		Repo             string
		CreateRepo       bool
		GsName           string
		RuntimeName      string
		RuntimeNamespace string
		Exclude          string
		Include          string
	}

	GitSourceDeleteOptions struct {
		RuntimeName string
		GsName      string
		Timeout     time.Duration
	}

	GitSourceEditOptions struct {
		RuntimeName string
		GsName      string
		Repo        string
		Include     *string
		Exclude     *string
	}
)

func newGitSourceCommand() *cobra.Command {
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

	cmd.AddCommand(newGitSourceCreateCommand())
	cmd.AddCommand(newGitSourceListCommand())
	cmd.AddCommand(newGitSourceDeleteCommand())
	cmd.AddCommand(newGitSourceEditCommand())

	return cmd
}

func newGitSourceCreateCommand() *cobra.Command {
	var (
		repo       string
		createRepo bool
		include    string
		exclude    string
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

			if repo == "" {
				log.G(ctx).Fatal("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name/path/to/workflow")
			}

			isValid, err := IsValidName(args[1])
			if err != nil {
				log.G(ctx).Fatal("failed to check the validity of the git-source name")
			}

			if !isValid {
				log.G(ctx).Fatal("git-source name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			runtimeName := args[0]
			runtime, err := getRuntime(ctx, runtimeName)
			if err != nil {
				return err
			}

			runtimeNamespace := runtimeName
			if runtime.Metadata.Namespace != nil {
				runtimeNamespace = *runtime.Metadata.Namespace
			}

			return runGitSourceCreate(ctx, &GitSourceCreateOptions{
				Repo:             repo,
				CreateRepo:       createRepo,
				GsName:           args[1],
				RuntimeName:      runtimeName,
				RuntimeNamespace: runtimeNamespace,
				Include:          include,
				Exclude:          exclude,
			})
		},
	}

	cmd.Flags().BoolVar(&createRepo, "create-repo", false, "If true, will create the specified git-source repo in case it doesn't already exist")
	cmd.Flags().StringVar(&include, "include", "", "files to include. can be either filenames or a glob")
	cmd.Flags().StringVar(&exclude, "exclude", "", "files to exclude. can be either filenames or a glob")
	cmd.Flags().StringVar(&repo, "git-source-repo", "", "Repository URL [%sGIT_SOURCE_GIT_REPO]")

	util.Die(viper.BindEnv("git-source-repo", "GIT_SOURCE_GIT_REPO"))

	return cmd
}

func runGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	isInternal := util.StringIndexOf(store.Get().CFInternalGitSources, opts.GsName) > -1

	err = appProxy.GitSource().Create(ctx, &apmodel.CreateGitSourceInput{
		AppName:       opts.GsName,
		AppSpecifier:  opts.Repo,
		DestServer:    store.Get().InClusterServerURL,
		DestNamespace: &opts.RuntimeNamespace,
		IsInternal:    &isInternal,
		Include:       &opts.Include,
		Exclude:       &opts.Exclude,
		CreateRepo:    &opts.CreateRepo,
	})
	if err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	log.G(ctx).Infof("Successfully created git-source: \"%s\"", opts.GsName)
	return nil
}

func newGitSourceListCommand() *cobra.Command {
	var (
		runtimeName     string
		includeInternal bool
	)

	cmd := &cobra.Command{
		Use:     "list RUNTIME_NAME",
		Short:   "List all Codefresh git-sources of a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> git-source list my-runtime`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			runtimeName, err = ensureRuntimeName(cmd.Context(), args, nil)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGitSourceList(cmd.Context(), runtimeName, includeInternal)
		},
	}

	cmd.Flags().BoolVar(&includeInternal, "include-internal", false, "If true, will include the Codefresh internal git-sources")

	return cmd
}

func runGitSourceList(ctx context.Context, runtimeName string, includeInternal bool) error {
	isRuntimeExists := checkExistingRuntimes(ctx, runtimeName)
	if isRuntimeExists == nil {
		return fmt.Errorf("there is no runtime by the name: %s", runtimeName)
	}

	gitSources, err := cfConfig.NewClient().GraphQL().GitSource().List(ctx, runtimeName)
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

func newGitSourceDeleteCommand() *cobra.Command {
	var (
		runtimeName string
		gsName      string
	)

	cmd := &cobra.Command{
		Use:   "delete RUNTIME_NAME GITSOURCE_NAME",
		Short: "delete a git-source from a runtime",
		Args:  cobra.MaximumNArgs(2),
		Example: util.Doc(`
			<BIN> git-source delete runtime_name git-source_name 
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			store.Get().Silent = true

			runtimeName, err = ensureRuntimeName(cmd.Context(), args, nil)
			if err != nil {
				return err
			}

			if len(args) < 2 {
				return fmt.Errorf("must enter git-source name")
			}

			gsName = args[1]
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGitSourceDelete(cmd.Context(), &GitSourceDeleteOptions{
				RuntimeName: runtimeName,
				GsName:      gsName,
				Timeout:     util.MustParseDuration(cmd.Flag("request-timeout").Value.String()),
			})
		},
	}

	return cmd
}

func runGitSourceDelete(ctx context.Context, opts *GitSourceDeleteOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.GitSource().Delete(ctx, opts.GsName)
	if err != nil {
		return fmt.Errorf("failed to delete git-source: %w", err)
	}

	log.G(ctx).Infof("Successfully deleted the git-source: %s", opts.GsName)
	return nil
}

func newGitSourceEditCommand() *cobra.Command {
	var (
		runtimeName string
		gsName      string
		repo        string
		include     string
		exclude     string
	)

	cmd := &cobra.Command{
		Use:   "edit RUNTIME_NAME GITSOURCE_NAME",
		Short: "edit a git-source of a runtime",
		Args:  cobra.MaximumNArgs(2),
		Example: util.Doc(`
			<BIN> git-source edit runtime_name git-source_name --git-src-repo https://github.com/owner/repo-name.git/path/to/dir
		`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			store.Get().Silent = true

			runtimeName, err = ensureRuntimeName(cmd.Context(), args, nil)
			if err != nil {
				return err
			}

			if len(args) < 2 {
				return fmt.Errorf("must enter a git-source name")
			}

			gsName = args[1]
			if repo == "" {
				return fmt.Errorf("must enter a valid value to --git-src-repo. Example: https://github.com/owner/repo-name.git/path/to/dir")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			opts := &GitSourceEditOptions{
				RuntimeName: runtimeName,
				GsName:      gsName,
				Repo:        repo,
			}

			if cmd.Flags().Changed("include") {
				opts.Include = &include
			}

			if cmd.Flags().Changed("exclude") {
				opts.Exclude = &exclude
			}

			return runGitSourceEdit(ctx, opts)
		},
	}

	cmd.Flags().StringVar(&include, "include", "", "files to include. can be either filenames or a glob")
	cmd.Flags().StringVar(&exclude, "exclude", "", "files to exclude. can be either filenames or a glob")
	cmd.Flags().StringVar(&repo, "git-source-repo", "", "Repository URL [%sGIT_SOURCE_GIT_REPO]")

	return cmd
}

func runGitSourceEdit(ctx context.Context, opts *GitSourceEditOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.GitSource().Edit(ctx, &apmodel.EditGitSourceInput{
		AppName:      opts.GsName,
		AppSpecifier: opts.Repo,
		Include:      opts.Include,
		Exclude:      opts.Exclude,
	})
	if err != nil {
		return fmt.Errorf("failed to edit git-source: %w", err)
	}

	log.G(ctx).Infof("Successfully edited git-source: \"%s\"", opts.GsName)
	return nil
}
