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
	bitbucketServer struct {
		providerType ProviderType
		apiURL       *url.URL
		c            *http.Client
	}

	createRepoBody struct {
		Name string `json:"name"`
	}
)

const (
	BITBUCKET_SERVER_REST_ENDPOINT              = "/rest/api/1.0"
	BITBUCKET_SERVER               ProviderType = "bitbucket-server"
)

func NewBitbucketServerProvider(baseURL string, client *http.Client) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	u.Path = BITBUCKET_SERVER_REST_ENDPOINT
	return &bitbucketServer{
		providerType: BITBUCKET_SERVER,
		apiURL:       u,
		c:            client,
	}, nil
}

func (bbs *bitbucketServer) BaseURL() string {
	urlClone := *bbs.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.String()
}

func (bbs *bitbucketServer) SupportsMarketplace() bool {
	return false
}

func (bbs *bitbucketServer) Type() ProviderType {
	return bbs.providerType
}

func (bbs *bitbucketServer) VerifyRuntimeToken(ctx context.Context, token string, username *string) error {
	return bbs.checkProjectAdminPermission(ctx, token)
}

func (bbs *bitbucketServer) VerifyUserToken(ctx context.Context, token string, username *string) error {
	return bbs.checkRepoReadPermission(ctx, token)
}

// POST to users/<username>/repos with an invalid repo name (starts with "!").
// if it returns 400 - the token has "Project admin" permission
// otherwise - the token does not have the permission
func (bbs *bitbucketServer) checkProjectAdminPermission(ctx context.Context, token string) error {
	username, err := bbs.getCurrentUsername(ctx, token)
	if err != nil {
		return fmt.Errorf("failed checking Project admin permission: %w", err)
	}

	urlPath := fmt.Sprintf("users/%s/repos", username)
	body := &createRepoBody{
		Name: "!invalid",
	}
	res, err := bbs.request(ctx, token, http.MethodPost, urlPath, body)
	if err != nil {
		return fmt.Errorf("failed checking Project admin permission: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		return errors.New("git-token is invalid or missing required \"Project admin\" scope")
	}

	return nil
}

// if there is no username in the response headers - that means the token was invalid.
// in bitbucket-server - all tokens have "Repository read" permission.
// the only way to not have this permission, is to use an invalid token.
func (bbs *bitbucketServer) checkRepoReadPermission(ctx context.Context, token string) error {
	_, err := bbs.getCurrentUsername(ctx, token)
	if err != nil {
		return fmt.Errorf("failed checking Repo read permission: %w", err)
	}

	return nil
}

// HEAD to application-properties - this endpoint does not require any permission (or auth header).
// but any request with a valid token has the X-AUSERNAME response header with the user name in it.
func (bbs *bitbucketServer) getCurrentUsername(ctx context.Context, token string) (string, error) {
	res, err := bbs.request(ctx, token, http.MethodHead, "application-properties", nil)
	if err != nil {
		return "", fmt.Errorf("failed getting current user: %w", err)
	}
	defer res.Body.Close()

	username := res.Header.Get("X-AUSERNAME")
	if username == "" {
		return "", errors.New("invalid token")
	}

	return username, nil
}

func (bbs *bitbucketServer) request(ctx context.Context, token, method, urlPath string, body interface{}) (*http.Response, error) {
	urlClone := *bbs.apiURL
	urlClone.Path = path.Join(urlClone.Path, urlPath)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	}
	req, err := httputil.NewRequest(ctx, method, urlClone.String(), headers, body)
	if err != nil {
		return nil, err
	}

	return bbs.c.Do(req)
}
