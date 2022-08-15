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
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/log"
	httputil "github.com/codefresh-io/cli-v2/pkg/util/http"
)

type (
	bitbucketServer struct {
		providerType ProviderType
		apiURL       *url.URL
	}

	createRepoBody struct {
		Name string `json:"name"`
	}
)

const (
	BITBUCKET_REST_ENDPOINT              = "/rest/api/1.0"
	BITBUCKET_SERVER        ProviderType = "bitbucket-server"
)

func NewBitbucketServerProvider(baseURL string) (Provider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	u.Path = BITBUCKET_REST_ENDPOINT
	return &bitbucketServer{
		providerType: BITBUCKET_SERVER,
		apiURL:       u,
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

func (bbs *bitbucketServer) VerifyRuntimeToken(ctx context.Context, token string) error {
	return bbs.checkAdminScope(ctx, token)
}

func (bbs *bitbucketServer) VerifyUserToken(ctx context.Context, token string) error {
	log.G(ctx).Debug("Skip verifying user token for bitbucket, to be implemented later")
	return nil
}

func (bbs *bitbucketServer) checkAdminScope(ctx context.Context, token string) error {
	username, err := bbs.getCurrentUser(ctx, token)
	if err != nil {
		return err
	}

	urlPath := fmt.Sprintf("users/%s/repos", username)
	body := &createRepoBody{
		Name: "!invalid",
	}
	res, err := bbs.request(ctx, token, http.MethodPost, urlPath, body)
	if err != nil {
		return fmt.Errorf("failed creating user repo: %w", err)
	}

	if res.StatusCode != http.StatusBadRequest {
		return errors.New("token is invalid or missing required \"admin\" scope")
	}

	return nil
}

func (bbs *bitbucketServer) getCurrentUser(ctx context.Context, token string) (string, error) {
	res, err := bbs.request(ctx, token, http.MethodGet, "/plugins/servlet/applinks/whoami", nil)
	if err != nil {
		return "", fmt.Errorf("failed getting current user: %w", err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read from response body: %w", err)
	}

	return string(data), nil

}

func (bbs *bitbucketServer) request(ctx context.Context, token, method, urlPath string, body interface{}) (*http.Response, error) {
	urlClone := *bbs.apiURL
	if strings.HasPrefix(urlPath, "/") {
		urlClone.Path = urlPath
	} else {
		urlClone.Path = path.Join(urlClone.Path, urlPath)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}

	return httputil.Request(ctx, method, urlClone.String(), headers, body)
}
