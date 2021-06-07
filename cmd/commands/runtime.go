package commands

import (
	"context"
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	RuntimeCreateOptions struct {
		RuntimeName string
		KubeContext string
		KubeFactory kube.Factory
		installRepo *apcmd.RepoCreateOptions
		// gitSrcRepo  *apcmd.RepoCreateOptions
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
		f           kube.Factory
		installRepo *apcmd.RepoCreateOptions
		//gitSrcRepo  *apcmd.RepoCreateOptions
	)

	cmd := &cobra.Command{
		Use:   "create [runtime_name]",
		Short: "Create a new Codefresh runtime",
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export INSTALL_GIT_TOKEN=<token>

# or with the flag:

		--install-git-token <token>

# Adds a new runtime

	<BIN> runtime create runtime-name --install-owner owner --install-name gitops_repo
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := &RuntimeCreateOptions{
				KubeContext: "",
				KubeFactory: f,
				installRepo: installRepo,
				// gitSrcRepo:  gitSrcRepo,
			}
			if len(args) < 1 {
				log.G().Fatal("must enter runtime name")
			}

			opts.RuntimeName = args[0]
			installRepo.Public = false
			return RunRuntimeCreate(cmd.Context(), opts)
		},
	}

	installRepo = apcmd.AddRepoCreateFlags(cmd, "install")
	// gitSrcRepo = apcmd.AddRepoCreateFlags(cmd, "git-src")
	f = kube.AddFlags(cmd.Flags())

	return cmd
}

func RunRuntimeCreate(ctx context.Context, opts *RuntimeCreateOptions) error {
	installOpts, err := apcmd.RunRepoCreate(ctx, opts.installRepo)
	if err != nil {
		return err
	}
	// var err error
	// installOpts := &git.CloneOptions{
	// 	Repo: "https://github.com/noam-codefresh/demo",
	// 	FS:   memfs.New(),
	// 	Auth: git.Auth{
	// 		Password: "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",
	// 	},
	// }
	// installOpts.Parse()

	err = apcmd.RunRepoBootstrap(ctx, &apcmd.RepoBootstrapOptions{
		AppSpecifier: store.Get().ArgoCDManifestsURL,
		Namespace:    opts.RuntimeName,
		KubeContext:  opts.KubeContext,
		KubeFactory:  opts.KubeFactory,
		CloneOptions: installOpts,
	})
	if err != nil {
		return err
	}

	err = apcmd.RunProjectCreate(ctx, &apcmd.ProjectCreateOptions{
		CloneOpts:   installOpts,
		ProjectName: opts.RuntimeName,
	})
	if err != nil {
		return err
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "events", store.Get().ArgoEventsManifestsURL, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application events: %w", err)
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "rollouts", store.Get().ArgoRolloutsManifestsURL, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application rollouts: %w", err)
	}

	if err = createApp(ctx, installOpts, opts.RuntimeName, "workflows", store.Get().ArgoWorkflowsManifestsURL, opts.RuntimeName); err != nil {
		return fmt.Errorf("failed to create application workflows: %w", err)
	}

	tokenSecret, err := getTokenSecret(opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to create codefresh token secret: %w", err)
	}

	if err = opts.KubeFactory.Apply(ctx, opts.RuntimeName, tokenSecret); err != nil {
		return fmt.Errorf("failed to create codefresh token: %w", err)
	}

	return nil
}

func createApp(ctx context.Context, cloneOpts *git.CloneOptions, projectName, appName, appURL, namespace string) error {
	return apcmd.RunAppCreate(ctx, &apcmd.AppCreateOptions{
		CloneOpts:   cloneOpts,
		ProjectName: projectName,
		AppOpts: &application.CreateOptions{
			AppName:       appName,
			AppType:       application.AppTypeKustomize,
			AppSpecifier:  appURL,
			DestNamespace: namespace,
		},
	})
}

func getTokenSecret(namespace string) ([]byte, error) {
	token := cfConfig.GetCurrentContext().Token

	return yaml.Marshal(&v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().CFTokenSecret,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"token": []byte(token),
		},
	})
}
