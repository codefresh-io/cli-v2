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
	"strings"
)

type (
	TokenType    string
	ProviderType string

	// Provider represents a git provider
	Provider interface {
		Type() ProviderType
		ApiUrl() string
		VerifyToken(ctx context.Context, tokenType TokenType, token string) error
		SupportsMarketplace() bool
	}
)

const (
	RuntimeToken  TokenType = "runtime token"
	PersonalToken TokenType = "personal token"
)

var (
	providers = map[ProviderType]func(string) (Provider, error){
		BITBUCKET_SERVER:    NewBitbucketServerProvider,
		GITHUB_CLOUD:        NewGithubCloudProvider,
		GITHUB_ENT:          NewGithubEnterpriseProvider,
		GITLAB_CLOUD:        NewGitlabCloudProvider,
		GITLAB_SELF_MANAGED: NewGitlabSelfManagedProvider,
	}
)

func GetProvider(providerType ProviderType, cloneURL string) (Provider, error) {
	if providerType != "" {
		fn := providers[providerType]
		if fn == nil {
			return nil, fmt.Errorf("invalid git provider %s", providerType)
		}

		return fn(cloneURL)
	}

	if strings.Contains(cloneURL, GITHUB_CLOUD_DOMAIN) {
		return NewGithubCloudProvider(cloneURL)
	}

	if strings.Contains(cloneURL, GITLAB_CLOUD_DOMAIN) {
		return NewGitlabCloudProvider(cloneURL)
	}

	return nil, fmt.Errorf("failed getting provider for clone url %s", cloneURL)
}
