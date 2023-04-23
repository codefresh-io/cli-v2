// Copyright 2023 The Codefresh Authors.
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
	"net/url"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/manifoldco/promptui"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

//go:generate mockgen -destination=./mocks/roundTripper.go -package=mocks net/http RoundTripper

type (
	ProviderType string

	// Provider represents a git provider
	Provider interface {
		ApiURL() string
		BaseURL() string
		SupportsMarketplace() bool
		IsCloud() bool
		Type() ProviderType
		VerifyRuntimeToken(ctx context.Context, auth apgit.Auth) error
		VerifyUserToken(ctx context.Context, auth apgit.Auth) error
		ValidateToken(ctx context.Context, auth apgit.Auth) error
	}
)

var (
	CYAN        = "\033[36m"
	COLOR_RESET = "\033[0m"

	cloudProvidersByDomain = map[string]ProviderType{
		BITBUCKET_CLOUD_DOMAIN: BITBUCKET,
		GITHUB_CLOUD_DOMAIN:    GITHUB,
		GITLAB_CLOUD_DOMAIN:    GITLAB,
	}

	providersByType = map[ProviderType]func(string, *http.Client) (Provider, error){
		BITBUCKET:        NewBitbucketProvider,
		BITBUCKET_SERVER: NewBitbucketServerProvider,
		GITHUB:           NewGithubProvider,
		GITHUB_ENT:       NewGithubProvider, // for backward compatability
		GITLAB:           NewGitlabProvider,
	}

	legalProviders = maps.Keys(providersByType)
	GetProvider    = getProvider
)

func (pt *ProviderType) String() string {
	if pt == nil {
		return ""
	}

	return string(*pt)
}

func (pt *ProviderType) Set(s string) error {
	*pt = ProviderType(s)
	if !slices.Contains(legalProviders, *pt) {
		return fmt.Errorf("value \"%s\" does not match ProviderType", s)
	}

	return nil
}

func (pt *ProviderType) Type() string {
	return "ProviderType"
}

func getProvider(providerType ProviderType, cloneURL, certFile string) (Provider, error) {
	transport, err := apgit.DefaultTransportWithCa(certFile)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
	}

	u, err := url.Parse(cloneURL)
	if err != nil {
		return nil, err
	}

	inferredType, ok := cloudProvidersByDomain[u.Hostname()]
	if ok {
		if providerType != "" && providerType != inferredType {
			return nil, fmt.Errorf("supplied provider \"%s\" does not match inferred cloud provider \"%s\" for url \"%s\"", providerType, inferredType, cloneURL)
		}

		providerType = inferredType
	}

	if providerType != "" {
		fn, ok := providersByType[providerType]
		if !ok {
			return nil, fmt.Errorf("invalid git provider %s", providerType)
		}

		return fn(cloneURL, client)
	}

	if !store.Get().Silent {
		provider := getGitProviderFromUserSelect(cloneURL, client)
		if provider != nil {
			return provider, nil
		}
	}

	return nil, fmt.Errorf("failed getting git provider for url %s", cloneURL)
}

func getGitProviderFromUserSelect(baseURL string, client *http.Client) Provider {
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
		Items:     maps.Keys(providers),
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
