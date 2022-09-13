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
	"strings"

	"encoding/base64"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	httputil "github.com/codefresh-io/cli-v2/pkg/util/http"
)

type (
	bitbucket struct {
		providerType ProviderType
		apiURL       *url.URL
		c            *http.Client
	}
)

const (
	BITBUCKET_CLOUD_DOMAIN               = "bitbucket.org"
	BITBUCKET_REST_ENDPOINT              = "/api/2.0"
	BITBUCKET               ProviderType = "bitbucket"
)

var (
	patScopes = [][]string{
		{"repository:admin", "repository:write"},
		{"account:read", "account:write"},
		{"team", "team:write"},
	}

	runtimeScopes = [][]string{
		{"repository:admin"},
		{"account:read", "account:write"},
		{"team", "team:write"},
		{"webhook"},
	}
)

func NewBitbucketProvider(baseURL string, client *http.Client) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	u.Path = BITBUCKET_REST_ENDPOINT
	return &bitbucket{
		providerType: BITBUCKET,
		apiURL:       u,
		c:            client,
	}, nil
}

func (bb *bitbucket) BaseURL() string {
	urlClone := *bb.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.String()
}

func (bb *bitbucket) SupportsMarketplace() bool {
	return false
}

func (bb *bitbucket) Type() ProviderType {
	return bb.providerType
}

func (bb *bitbucket) VerifyRuntimeToken(ctx context.Context, auth apgit.Auth) error {
	if auth.Password == "" {
		return fmt.Errorf("user name is require for bitbucket cloud request")
	}

	return bb.verifyToken(ctx, auth.Password, auth.Username, runtimeScopes)
}

func (bb *bitbucket) VerifyUserToken(ctx context.Context, auth apgit.Auth) error {
	if auth.Password == "" {
		return fmt.Errorf("user name is require for bitbucket cloud request")
	}
	return bb.verifyToken(ctx, auth.Password, auth.Username, patScopes)
}

func (bb *bitbucket) verifyToken(ctx context.Context, token string, username string, requiredScopes [][]string) error {
	scopes, err := bb.getCurrentUserScopes(ctx, token, username)
	if err != nil {
		return fmt.Errorf("failed checking token scope permission: %w", err)
	}
	for _, requiredScope := range requiredScopes {
		isScopeIncluded := false
		for _, scopeOpt := range requiredScope {
			if strings.Contains(scopes, scopeOpt) {
				isScopeIncluded = true
			}
		}
		if !isScopeIncluded {
			return fmt.Errorf("the provided token is missing required token scopes, got: %s required: %v", scopes, requiredScopes)
		}
	}

	return nil
}

func (bb *bitbucket) getCurrentUserScopes(ctx context.Context, token, username string) (string, error) {
	res, err := bb.request(ctx, username, token, http.MethodHead, "user", nil)
	if err != nil {
		return "", fmt.Errorf("failed getting current user: %w", err)
	}
	defer res.Body.Close()

	scopes := res.Header.Get("x-oauth-scopes")

	if scopes == "" {
		return "", errors.New("invalid token")
	}

	return scopes, nil
}

func (bb *bitbucket) request(ctx context.Context, username, token, method, urlPath string, body interface{}) (*http.Response, error) {
	urlClone := *bb.apiURL
	urlClone.Path = path.Join(urlClone.Path, urlPath)
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	headers := map[string]string{
		"Authorization": "Basic " + auth,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	}
	req, err := httputil.NewRequest(ctx, method, urlClone.String(), headers, body)
	if err != nil {
		return nil, err
	}

	return bb.c.Do(req)
}
