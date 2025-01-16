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

// Copyright 2024 The Codefresh Authors.
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
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	httputil "github.com/codefresh-io/cli-v2/pkg/util/http"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
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

	scopesApiMap = map[string]string{
		"account:read account:write":        "account:read",
		"repository:admin repository:write": "repository:write",
		"repository:admin":                  "repository:admin",
		"team team:write":                   "workspace membership:write (team:write)",
		"webhook":                           "webhook:read and write",
	}
)

func NewBitbucketProvider(baseURL string, client *http.Client) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if u.Host != BITBUCKET_CLOUD_DOMAIN {
		return nil, fmt.Errorf("wrong domain for bitbucket provider: \"%s\", expected \"%s\"\n  maybe you meant to use \"bitbucket-server\" for on-prem git provider?", baseURL, BITBUCKET_CLOUD_DOMAIN)
	}

	u.Path = BITBUCKET_REST_ENDPOINT
	return &bitbucket{
		providerType: BITBUCKET,
		apiURL:       u,
		c:            client,
	}, nil
}

func (bb *bitbucket) ApiURL() string {
	return bb.apiURL.String()
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

func (_ *bitbucket) IsCloud() bool {
	return true
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

func (bb *bitbucket) ValidateToken(ctx context.Context, auth apgit.Auth) error {
	if auth.Username == "" {
		return fmt.Errorf("user name is require for bitbucket cloud request")
	}

	res, err := bb.request(ctx, auth.Username, auth.Password, http.MethodHead, "user", nil)
	if err != nil {
		return fmt.Errorf("failed getting current user: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode == 401 {
		return fmt.Errorf("invalid token")
	}
	return nil
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
			var requestedScopes = bb.getRequestedScopes(requiredScopes)
			return fmt.Errorf("the provided token is missing required token scopes, got: %s \nrequired: %v", scopes, requestedScopes)
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

func (bb *bitbucket) getRequestedScopes(requiredScopes [][]string) string {
	var requestedScopes string = ""

	for _, requiredScopeOpts := range requiredScopes {
		var scopeOpts = ""
		for _, requiredScope := range requiredScopeOpts {
			if len(scopeOpts) > 0 {
				scopeOpts += " "
			}
			scopeOpts += requiredScope
		}

		if len(requestedScopes) > 0 {
			requestedScopes += ", "
		}

		if len(scopesApiMap[scopeOpts]) > 0 {
			requestedScopes += scopesApiMap[scopeOpts]
		} else {
			requestedScopes += scopeOpts
		}
	}

	return requestedScopes
}
