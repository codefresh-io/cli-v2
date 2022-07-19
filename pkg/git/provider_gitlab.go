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
	GITLAB_CLOUD_DOMAIN               = "gitlab.com"
	GITLAB_REST_ENDPOINT              = "/api/v4"
	GITLAB               ProviderType = "gitlab"
)

func NewGitlabProvider(cloneURL string) (Provider, error) {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return nil, err
	}

	u.Path = ""
	return &gitlab{
		providerType: GITLAB,
		apiURL:       u.String(),
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
