// Copyright 2025 The Codefresh Authors.
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

	httputil "github.com/codefresh-io/cli-v2/internal/util/http"
)

type (
	github struct {
		providerType ProviderType
		apiURL       *url.URL
		c            *http.Client
	}
)

const (
	GITHUB_CLOUD_DOMAIN               = "github.com"
	GITHUB_CLOUD_API_URL              = "https://api.github.com"
	GITHUB_REST_ENDPOINT              = "/api/v3"
	GITHUB               ProviderType = "github"
	GITHUB_ENT           ProviderType = "github-enterpeise" // for backward compatability
)

var runtime_token_scopes = []string{"repo", "admin:repo_hook"}

func NewGithubProvider(baseURL string, client *http.Client) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if u.Host == GITHUB_CLOUD_DOMAIN {
		u, _ = url.Parse(GITHUB_CLOUD_API_URL)
	} else if u.Path == "" {
		u.Path = GITHUB_REST_ENDPOINT
	}

	return &github{
		providerType: GITHUB,
		apiURL:       u,
		c:            client,
	}, nil
}

func (g *github) ApiURL() string {
	return g.apiURL.String()
}

func (g *github) IsCloud() bool {
	return g.ApiURL() == GITHUB_CLOUD_API_URL
}

func (g *github) Type() ProviderType {
	return g.providerType
}

func (g *github) VerifyRuntimeToken(ctx context.Context, auth Auth) error {
	tokenType, err := g.getTokenType(auth.Password)
	if err != nil {
		return fmt.Errorf("failed getting token type: %w", err)
	}

	if tokenType == "fine-grained" {
		return fmt.Errorf("validation for github fine-grained PAT is not supported yet, please retry with --skip-permissions-validation or use a classic token")
	}

	err = g.verifyToken(ctx, auth.Password, runtime_token_scopes)
	if err != nil {
		return fmt.Errorf("invalid git-token: %w", err)
	}

	return nil
}

func (g *github) getTokenType(token string) (string, error) {
	if token == "" {
		return "", errors.New("missing token")
	}
	if strings.HasPrefix(token, "github_pat") {
		return "fine-grained", nil
	}
	return "classic", nil
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
