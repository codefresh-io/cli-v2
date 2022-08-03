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
	"net/url"
	"strings"
)

type (
	github struct {
		providerType ProviderType
		apiURL       *url.URL
	}
)

const (
	GITHUB_CLOUD_DOMAIN                = "github.com"
	GITHUB_CLOUD_BASE_URL              = "https://github.com/"
	GITHUB_CLOUD_API_URL               = "https://api.github.com"
	GITHUB_REST_ENDPOINT               = "/api/v3"
	GITHUB                ProviderType = "github"
	GITHUB_ENT            ProviderType = "github-enterpeise" // for backward compatability
)

var requiredScopes = map[TokenType][]string{
	RuntimeToken:  {"repo", "admin:repo_hook"},
	PersonalToken: {"repo"},
}

func NewGithubProvider(baseURL string) (Provider, error) {
	if baseURL == GITHUB_CLOUD_BASE_URL {
		baseURL = GITHUB_CLOUD_API_URL
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if baseURL != GITHUB_CLOUD_API_URL {
		u.Path = GITHUB_REST_ENDPOINT
	}

	return &github{
		providerType: GITHUB,
		apiURL:       u,
	}, nil
}

func (g *github) Type() ProviderType {
	return g.providerType
}

func (g *github) BaseURL() string {
	urlClone := *g.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.Host
}

func (g *github) VerifyToken(ctx context.Context, tokenType TokenType, token string) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", g.apiURL.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	rawScopes := resp.Header["X-Oauth-Scopes"]
	var scopes []string
	if len(rawScopes) > 0 {
		scopes = strings.Split(rawScopes[0], ", ")
	}

	for _, rs := range requiredScopes[tokenType] {
		var contained bool
		for _, scope := range scopes {
			if scope == rs {
				contained = true
				break
			}
		}

		if !contained {
			return fmt.Errorf("the provided %s is missing one or more of the required scopes: %s", tokenType, strings.Join(requiredScopes[tokenType], ", "))
		}
	}

	return nil
}

func (g *github) SupportsMarketplace() bool {
	return true
}
