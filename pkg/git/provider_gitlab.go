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
	"net/url"
)

type (
	gitlab struct {
		providerType ProviderType
		apiURL       string
	}
)

const (
	GITLAB_CLOUD_DOMAIN              = "gitlab.com"
	GITLAB_CLOUD        ProviderType = "gitlab"
	GITLAB_SELF_MANAGED ProviderType = "gitlab-self-managed"
)

func NewGitlabCloudProvider(_ string) (Provider, error) {
	return &gitlab{
		providerType: GITLAB_CLOUD,
		apiURL: "https://gitlab.com/api/v4",
	}, nil
}

func NewGitlabSelfManagedProvider(cloneURL string) (Provider, error) {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return nil, err
	}

	return &gitlab{
		providerType: GITLAB_SELF_MANAGED,
		apiURL: u.Host + "/api/scim/v2",
	}, nil
}

func (g *gitlab) Type() ProviderType {
	return g.providerType
}

func (g *gitlab) ApiUrl() string {
	return g.apiURL
}

func (g *gitlab) VerifyToken(ctx context.Context, tokenType TokenType, token string) error {
	return nil
}

func (g *gitlab) SupportsMarketplace() bool {
	return false
}
