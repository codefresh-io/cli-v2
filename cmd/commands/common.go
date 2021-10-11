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
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/config"
	"github.com/codefresh-io/cli-v2/pkg/util"

	gh "github.com/google/go-github/v39/github"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	die  = util.Die
	exit = os.Exit

	//go:embed assets/ingress-patch.json
	ingressPatch []byte

	cfConfig *config.Config
)

// type github struct {
// 	opts         *ProviderOptions
// 	Repositories g.Repositories
// 	Users        g.Users
// }

// type ProviderOptions struct {
// 	Type string
// 	Auth *Auth
// 	Host string
// }

func postInitCommands(commands []*cobra.Command) {
	for _, cmd := range commands {
		presetRequiredFlags(cmd)
		if cmd.HasSubCommands() {
			postInitCommands(cmd.Commands())
		}
	}
}

func presetRequiredFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && f.Value.String() == "" {
			die(cmd.Flags().Set(f.Name, viper.GetString(f.Name)))
		}
	})
	cmd.Flags().SortFlags = false
}

func IsValid(s string) (bool, error) {
	return regexp.MatchString(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`, s)
}

func ensureRepo(cmd *cobra.Command, args []string, cloneOpts *git.CloneOptions) error {
	ctx := cmd.Context()
	if cloneOpts.Repo == "" {
		runtimeData, err := cfConfig.NewClient().V2().Runtime().Get(ctx, args[0])
		if err != nil {
			return fmt.Errorf("Failed getting runtime repo information: %w", err)
		}
		if runtimeData.Repo != nil {
			cloneOpts.Repo = *runtimeData.Repo
			die(cmd.Flags().Set("repo", *runtimeData.Repo))
		}
	}
	return nil
}

func getLatestCliRelease(ctx context.Context, cloneOpts *git.CloneOptions) (string, error) {
	var (
		c *gh.Client
	)

	hc := &http.Client{}
	hc.Transport = &gh.BasicAuthTransport{
		Username: cloneOpts.Auth.Username,
		Password: cloneOpts.Auth.Password,
	}

	c = gh.NewClient(hc)

	latestRepositoryRelease, res, err := c.Repositories.ListReleases(ctx, "codefresh-io", "cli-v2", &gh.ListOptions{
		PerPage: 1,
	})

	if err != nil {
		return "", err
	}

	if res.StatusCode != 200 {
		return "", err
	}

	return *latestRepositoryRelease[0].Name, nil
}
