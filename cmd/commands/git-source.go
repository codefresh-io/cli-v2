// Copyright 2024 The Codefresh Authors.
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

	cfgit "github.com/codefresh-io/cli-v2/internal/git"
	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/store"
	"github.com/codefresh-io/cli-v2/internal/util"
	apu "github.com/codefresh-io/cli-v2/internal/util/aputil"
	routingutil "github.com/codefresh-io/cli-v2/internal/util/routing"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	apmodel "github.com/codefresh-io/go-sdk/pkg/model/app-proxy"
	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
)

type (
	GitSourceCreateOptions struct {
		InsCloneOpts        *apgit.CloneOptions
		GsCloneOpts         *apgit.CloneOptions
		GsName              string
		RuntimeName         string
		RuntimeNamespace    string
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
		RuntimeName string
		GsName      string
		Timeout     time.Duration
	}

	GitSourceEditOptions struct {
		RuntimeName string
		GsName      string
		GsCloneOpts *apgit.CloneOptions
		Include     *string
		Exclude     *string
	}
)

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
		gsCloneOpts *apgit.CloneOptions
		gitProvider cfgit.Provider
		createRepo  bool
		include     string
		exclude     string
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

			isValid, err := IsValidName(args[1])
			if err != nil {
				log.G(ctx).Fatal("failed to check the validity of the git-source name")
			}

			if !isValid {
				log.G(ctx).Fatal("git-source name cannot have any uppercase letters, must start with a character, end with character or number, and be shorter than 63 chars")
			}

			if createRepo {
				gsCloneOpts.CreateIfNotExist = createRepo
			}

			gsCloneOpts.Parse()

			baseURL, _, _, _, _, _, _ := aputil.ParseGitUrl(gsCloneOpts.Repo)
			gitProvider, err = cfgit.GetProvider(cfgit.ProviderType(gsCloneOpts.Provider), baseURL, gsCloneOpts.Auth.CertFile)
			if err != nil {
				log.G(ctx).Fatal("failed to infer git provider for git-source")
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

			return RunGitSourceCreate(ctx, &GitSourceCreateOptions{
				GsCloneOpts:         gsCloneOpts,
				GitProvider:         gitProvider,
				GsName:              args[1],
				RuntimeName:         runtimeName,
				RuntimeNamespace:    runtimeNamespace,
				CreateDemoResources: false,
				Include:             include,
				Exclude:             exclude,
			})
		},
	}

	cmd.Flags().BoolVar(&createRepo, "create-repo", false, "If true, will create the specified git-source repo in case it doesn't already exist")
	cmd.Flags().StringVar(&include, "include", "", "files to include. can be either filenames or a glob")
	cmd.Flags().StringVar(&exclude, "exclude", "", "files to exclude. can be either filenames or a glob")

	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:   "git-src",
		Optional: true,
	})

	return cmd
}

func RunGitSourceCreate(ctx context.Context, opts *GitSourceCreateOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	appSpecifier := opts.GsCloneOpts.Repo
	isInternal := util.StringIndexOf(store.Get().CFInternalGitSources, opts.GsName) > -1

	err = appProxy.GitSource().Create(ctx, &apmodel.CreateGitSourceInput{
		AppName:       opts.GsName,
		AppSpecifier:  appSpecifier,
		DestServer:    store.Get().InClusterServerURL,
		DestNamespace: &opts.RuntimeNamespace,
		IsInternal:    &isInternal,
		Include:       &opts.Include,
		Exclude:       &opts.Exclude,
	})
	if err != nil {
		return fmt.Errorf("failed to create git-source: %w", err)
	}

	log.G(ctx).Infof("Successfully created git-source: \"%s\"", opts.GsName)
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

func NewGitSourceDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RUNTIME_NAME GITSOURCE_NAME",
		Short: "delete a git-source from a runtime",
		Args:  cobra.MaximumNArgs(2),
		Example: util.Doc(`
			<BIN> git-source delete runtime_name git-source_name 
		`),
		PreRunE: func(_ *cobra.Command, args []string) error {
			store.Get().Silent = true

			if len(args) < 1 {
				return fmt.Errorf("must enter runtime name")
			}

			if len(args) < 2 {
				return fmt.Errorf("must enter git-source name")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			return RunGitSourceDelete(ctx, &GitSourceDeleteOptions{
				RuntimeName: args[0],
				GsName:      args[1],
				Timeout:     aputil.MustParseDuration(cmd.Flag("request-timeout").Value.String()),
			})
		},
	}

	return cmd
}

func RunGitSourceDelete(ctx context.Context, opts *GitSourceDeleteOptions) error {
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

func NewGitSourceEditCommand() *cobra.Command {
	var (
		gsCloneOpts *apgit.CloneOptions
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
		PreRunE: func(_ *cobra.Command, args []string) error {
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

			gsCloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			opts := &GitSourceEditOptions{
				RuntimeName: args[0],
				GsName:      args[1],
				GsCloneOpts: gsCloneOpts,
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

	gsCloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		Prefix:           "git-src",
		Optional:         true,
		CreateIfNotExist: true,
	})
	return cmd
}

func RunGitSourceEdit(ctx context.Context, opts *GitSourceEditOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.GitSource().Edit(ctx, &apmodel.EditGitSourceInput{
		AppName:      opts.GsName,
		AppSpecifier: opts.GsCloneOpts.Repo,
		Include:      opts.Include,
		Exclude:      opts.Exclude,
	})
	if err != nil {
		return fmt.Errorf("failed to edit git-source: %w", err)
	}

	log.G(ctx).Infof("Successfully edited git-source: \"%s\"", opts.GsName)
	return nil
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
