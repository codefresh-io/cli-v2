package commands

import (
	"context"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/spf13/cobra"
)

type (
	RuntimeCreateOptions struct {
		RuntimeName string
		KubeContext string
		KubeFactory kube.Factory
		rcOpts      *apcmd.RepoCreateOptions
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
		f      kube.Factory
		rcOpts *apcmd.RepoCreateOptions
	)

	cmd := &cobra.Command{
		Use:   "provision [runtime_name]",
		Short: "Create a new Codefresh runtime",
		Example: util.Doc(`
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := &RuntimeCreateOptions{
				KubeContext: "",
				KubeFactory: f,
				rcOpts:      rcOpts,
			}
			if len(args) < 1 {
				log.G().Fatal("must enter runtime name")
			}

			opts.RuntimeName = args[0]
			rcOpts.Public = false
			return RunRuntimeCreate(cmd.Context(), opts)
		},
	}

	rcOpts = apcmd.AddRepoCreateFlags(cmd)
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeCreate(ctx context.Context, opts *RuntimeCreateOptions) error {
	cOpts, err := apcmd.RunRepoCreate(ctx, opts.rcOpts)
	if err != nil {
		return err
	}

	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: store.Get().ArgoCDManifestsURL,
		Namespace:    opts.RuntimeName,
		KubeContext:  opts.KubeContext,
		KubeFactory:  opts.KubeFactory,
		FS:           fs.Create(memfs.New()),
		CloneOptions: cOpts,
	})
	if err != nil {
		return err
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		BaseOptions: apcmd.BaseOptions{
			CloneOptions: cOpts,
			FS:           fs.Create(memfs.New()),
		},
		Name: opts.RuntimeName,
	})
	if err != nil {
		return err
	}

	err = apcmd.RunAppCreate(ctx, &apcmd.AppCreateOptions{
		BaseOptions: apcmd.BaseOptions{
			CloneOptions: cOpts,
			FS:           fs.Create(memfs.New()),
			ProjectName:  opts.RuntimeName,
		},
		AppOpts: &application.CreateOptions{
			AppName:       "Argo CD",
			AppType:       application.AppTypeKustomize,
			AppSpecifier:  store.Get().ArgoCDManifestsURL,
			DestNamespace: opts.RuntimeName,
		},
	})
	if err != nil {
		return err
	}
	// autopilot repo create --owner --name -> cloneUrl
	// 					 repo bootstrap --repo --app
	//           project create codefresh
	//           app create workflows --app
	//           app create events --app
	//           app create rollouts --app
	return err
}
