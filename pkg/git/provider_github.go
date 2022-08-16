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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	httputil "github.com/codefresh-io/cli-v2/pkg/util/http"
)

type (
	github struct {
		providerType ProviderType
		apiURL       *url.URL
		c            *http.Client
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

var (
	runtime_token_scopes = []string{"repo", "admin:repo_hook"}
	user_token_scopes    = []string{"repo"}
)

func NewGithubProvider(baseURL string, client *http.Client) (Provider, error) {
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
		c:            client,
	}, nil
}

func (g *github) BaseURL() string {
	urlClone := *g.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.String()
}

func (g *github) SupportsMarketplace() bool {
	return true
}

func (g *github) Type() ProviderType {
	return g.providerType
}

func (g *github) VerifyRuntimeToken(ctx context.Context, token string) error {
	err := g.verifyToken(ctx, token, runtime_token_scopes)
	if err != nil {
		return fmt.Errorf("git-token invalid: %w", err)
	}

	return nil
}

func (g *github) VerifyUserToken(ctx context.Context, token string) error {
	err := g.verifyToken(ctx, token, user_token_scopes)
	if err != nil {
		return fmt.Errorf("personal-git-token invalid: %w", err)
	}

	return nil
}

func (g *github) verifyToken(ctx context.Context, token string, requiredScopes []string) error {
	reqHeaders := map[string]string{
		"Authorization": "token " + token,
	}
	req, err := httputil.NewRequest(ctx, http.MethodHead, g.apiURL.String(), reqHeaders, nil)
	if err != nil {
		return err
	}

	res, err := g.c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawScopes := res.Header.Get("X-Oauth-Scopes")
	if rawScopes == "" {
		return errors.New("missing scopes header on response")
	}

	var scopes []string
	if len(rawScopes) > 0 {
		scopes = strings.Split(rawScopes, ", ")
	}

	for _, rs := range requiredScopes {
		var contained bool
		for _, scope := range scopes {
			if scope == rs {
				contained = true
				break
			}
		}

		if !contained {
			return fmt.Errorf("the provided token is missing one or more of the required scopes: %s", strings.Join(requiredScopes, ", "))
		}
	}

	return nil
}
