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
	"path"

	httputil "github.com/codefresh-io/cli-v2/pkg/util/http"
)

type (
	gitlab struct {
		providerType ProviderType
		apiURL       *url.URL
	}
)

const (
	GITLAB_CLOUD_DOMAIN               = "gitlab.com"
	GITLAB_REST_ENDPOINT              = "/api/v4"
	GITLAB               ProviderType = "gitlab"
)

func NewGitlabProvider(baseURL string) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	u.Path = GITLAB_REST_ENDPOINT
	return &gitlab{
		providerType: GITLAB,
		apiURL:       u,
	}, nil
}

func (g *gitlab) BaseURL() string {
	urlClone := *g.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.String()
}

func (g *gitlab) SupportsMarketplace() bool {
	return false
}

func (g *gitlab) Type() ProviderType {
	return g.providerType
}

func (g *gitlab) VerifyRuntimeToken(ctx context.Context, token string) error {
	return g.checkApiScope(ctx, token)
}

func (g *gitlab) VerifyUserToken(ctx context.Context, token string) error {
	return g.checkReadRepositoryScope(ctx, token)
}

func (g *gitlab) checkApiScope(ctx context.Context, token string) error {
	res, err := g.request(ctx, token, http.MethodPost, "projects")
	if err != nil {
		return fmt.Errorf("failed checking api scope: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		return errors.New("git-token is invalid or missing required \"api\" scope")
	}

	return nil
}

func (g *gitlab) checkReadRepositoryScope(ctx context.Context, token string) error {
	res, err := g.request(ctx, token, http.MethodHead, "projects")
	if err != nil {
		return fmt.Errorf("failed checking read_repository scope: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("personal-git-token is invalid or missing required \"read_api\" or \"read_repository\" scope")
	}

	return nil
}

func (g *gitlab) request(ctx context.Context, token, method, urlPath string) (*http.Response, error) {
	urlClone := *g.apiURL
	urlClone.Path = path.Join(urlClone.Path, urlPath)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	}
	return httputil.Request(ctx, method, urlClone.String(), headers, nil)
}
