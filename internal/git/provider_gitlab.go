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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	httputil "github.com/codefresh-io/cli-v2/internal/util/http"
)

type (
	gitlab struct {
		providerType ProviderType
		apiURL       *url.URL
		c            *http.Client
	}

	gitlabUserResponse struct {
		Username string `json:"username"`
		Bot      bool   `json:"bot"`
	}
)

const (
	GITLAB_CLOUD_DOMAIN               = "gitlab.com"
	GITLAB_REST_ENDPOINT              = "/api/v4"
	GITLAB               ProviderType = "gitlab"
)

func NewGitlabProvider(baseURL string, client *http.Client) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if u.Host == GITLAB_CLOUD_DOMAIN || u.Path == "" {
		u.Path = GITLAB_REST_ENDPOINT
	}

	return &gitlab{
		providerType: GITLAB,
		apiURL:       u,
		c:            client,
	}, nil
}

func (g *gitlab) ApiURL() string {
	return g.apiURL.String()
}

func (g *gitlab) IsCloud() bool {
	return g.apiURL.Host == GITLAB_CLOUD_DOMAIN
}

func (g *gitlab) Type() ProviderType {
	return g.providerType
}

func (g *gitlab) VerifyRuntimeToken(ctx context.Context, auth Auth) error {
	return g.checkApiScope(ctx, auth.Password)
}

// POST to projects without a body.
// if it returns 400 - the token has "api" scope
// otherwise - the token does not have the scope
func (g *gitlab) checkApiScope(ctx context.Context, token string) error {

	tokenType, err := g.checkTokenType(token, ctx)
	if err != nil {
		return fmt.Errorf("failed checking api scope: %w", err)
	}

	if tokenType == "project" {
		return errors.New("runtime git-token is invalid, project token is not exceptable")
	}

	res, err := g.request(ctx, token, http.MethodPost, "projects")
	if err != nil {
		return fmt.Errorf("failed checking api scope: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		return errors.New("git-token is invalid or missing required \"api\" scope")
	}

	return nil
}

func (g *gitlab) checkTokenType(token string, ctx context.Context) (string, error) {
	userRes, err := g.request(ctx, token, http.MethodGet, "user")

	if err != nil {
		return "", fmt.Errorf("failed getting user: %w", err)
	}

	defer func() { _ = userRes.Body.Close() }()

	bodyBytes, err := io.ReadAll(userRes.Body)
	if err != nil {
		return "", fmt.Errorf("failed reading user body: %w", err)
	}

	var user gitlabUserResponse
	err = json.Unmarshal(bodyBytes, &user)
	if err != nil {
		return "", fmt.Errorf("failed parse user body: %w", err)
	}
	if user.Bot {
		if strings.HasPrefix(user.Username, "project") {
			return "project", nil
		}
		return "group", nil
	}

	return "personal", nil
}

func (g *gitlab) request(ctx context.Context, token, method, urlPath string) (*http.Response, error) {
	urlClone := *g.apiURL
	urlClone.Path = path.Join(urlClone.Path, urlPath)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	}
	req, err := httputil.NewRequest(ctx, method, urlClone.String(), headers, nil)
	if err != nil {
		return nil, err
	}

	return g.c.Do(req)
}
