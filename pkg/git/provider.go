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
)

//go:generate mockgen -destination=./mocks/roundTripper.go -package=mocks net/http RoundTripper

type (
	ProviderType string

	// Provider represents a git provider
	Provider interface {
		BaseURL() string
		SupportsMarketplace() bool
		Type() ProviderType
		VerifyRuntimeToken(ctx context.Context, token string) error
		VerifyUserToken(ctx context.Context, token string) error
	}
)

var providers = map[ProviderType]func(string, *http.Client) (Provider, error){
	BITBUCKET_SERVER: NewBitbucketServerProvider,
	GITHUB:           NewGithubProvider,
	GITHUB_ENT:       NewGithubProvider, // for backward compatability
	GITLAB:           NewGitlabProvider,
}

func GetProvider(providerType ProviderType, baseURL string) (Provider, error) {
	client := &http.Client{}
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

	return nil, fmt.Errorf("failed getting provider for clone url %s", baseURL)
}
