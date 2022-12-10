// Copyright 2022 The Codefresh Authors.
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

package git

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/manifoldco/promptui"
)

//go:generate mockgen -destination=./mocks/roundTripper.go -package=mocks net/http RoundTripper

var (
	CYAN        = "\033[36m"
	COLOR_RESET = "\033[0m"
)

type (
	ProviderType string

	// Provider represents a git provider
	Provider interface {
		BaseURL() string
		SupportsMarketplace() bool
		Type() ProviderType
		VerifyRuntimeToken(ctx context.Context, auth apgit.Auth) error
		VerifyUserToken(ctx context.Context, auth apgit.Auth) error
	}
)

var providers = map[ProviderType]func(string, *http.Client) (Provider, error){
	BITBUCKET:        NewBitbucketProvider,
	BITBUCKET_SERVER: NewBitbucketServerProvider,
	GITHUB:           NewGithubProvider,
	GITHUB_ENT:       NewGithubProvider, // for backward compatability
	GITLAB:           NewGitlabProvider,
}

func GetProvider(providerType ProviderType, baseURL, certFile string) (Provider, error) {
	transport, err := apgit.DefaultTransportWithCa(certFile)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
	}

	if providerType != "" {
		fn := providers[providerType]
		if fn == nil {
			return nil, fmt.Errorf("invalid git provider %s", providerType)
		}

		return fn(baseURL, client)
	}

	if strings.Contains(baseURL, GITHUB_CLOUD_DOMAIN) {
		return NewGithubProvider(baseURL, client)
	}

	if strings.Contains(baseURL, GITLAB_CLOUD_DOMAIN) {
		return NewGitlabProvider(baseURL, client)
	}

	if strings.Contains(baseURL, BITBUCKET_CLOUD_DOMAIN) {
		return NewBitbucketProvider(baseURL, client)
	}

	if !store.Get().Silent {
		provider := getGitProviderFromUserSelect(baseURL, client)
		if provider != nil {
			return provider, nil
		}
	}

	return nil, fmt.Errorf("failed getting provider for clone url %s", baseURL)
}

func getGitProviderFromUserSelect(baseURL string, client *http.Client) (Provider) {
	var providers = map[string]func(string, *http.Client) (Provider, error){
		"Bitbucket": NewBitbucketServerProvider,
		"GitHub":    NewGithubProvider,
		"GitLab":    NewGitlabProvider,
	}

	templates := &promptui.SelectTemplates{
		Selected: "{{ .Name | yellow }}",
	}

	labelStr := fmt.Sprintf("%vSelect git provider%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     []string{"GitHub", "GitLab", "Bitbucket"},
		Templates: templates,
	}

	_, label, err := prompt.Run()
	if err != nil {
		return nil
	}

	if fn, ok := providers[label]; ok {
		provider, _ := fn(baseURL, client)
		return provider
	}

	return nil
}
