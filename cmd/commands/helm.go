package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/spf13/cobra"
	"github.com/ghodss/yaml"
)

type HybridRuntimeValues struct {
	AccountId  string `yaml:"accountId"`
	IscRepoUrl string `yaml:"iscRepoUrl"`
}

func NewHelmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "helm",
		Short:             "Manage cf helm config",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewHelmGenerateValuesFilesCommand())

	return cmd
}

func NewHelmGenerateValuesFilesCommand() *cobra.Command {
	var values HybridRuntimeValues

	cmd := &cobra.Command{
		Use:     "generate",
		Short:   "Generate a helm values files",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> helm generate --isc-repo-url <ISC-REPO-URL>`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHelmGenerateValuesFile(cmd.Context(), &values)
		},
	}

	cmd.Flags().StringVar(&values.IscRepoUrl, "isc-repo-url", "", "The url of the ISC repo")

	return cmd
}

func runHelmGenerateValuesFile(ctx context.Context, values *HybridRuntimeValues) error {
	var err error
	user, err := cfConfig.NewClient().Users().GetCurrent(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current user from platform: %w", err)
	}


	values.AccountId, err = util.CurrentAccount(user)
	if err != nil {
		return err
	}

	return values.Save()
}

func (v *HybridRuntimeValues) Save() error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}

	if err = os.WriteFile("values.yaml", data, 0644); err != nil {
		return fmt.Errorf("Failed to write to file: %w", err)
	}

	return nil
}
