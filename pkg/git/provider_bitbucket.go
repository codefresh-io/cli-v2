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
	"net/http"
	"net/url"
	"path"

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
	BITBUCKET_REST_ENDPOINT              = "/2.0"
	BITBUCKET               ProviderType = "bitbucket"
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

func (bb *bitbucket) VerifyRuntimeToken(ctx context.Context, token string) error {
	return bb.checkProjectAdminPermission(ctx, token)
}

func (bb *bitbucket) VerifyUserToken(ctx context.Context, token string) error {
	return bb.checkRepoReadPermission(ctx, token)
}

//TODO impl
func (bb *bitbucket) checkProjectAdminPermission(ctx context.Context, token string) error {
	return nil
}

//TODO impl-
func (bb *bitbucket) checkRepoReadPermission(ctx context.Context, token string) error {
	return nil
}

func (bb *bitbucket) request(ctx context.Context, token, method, urlPath string, body interface{}) (*http.Response, error) {
	urlClone := *bb.apiURL
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

	return bb.c.Do(req)
}
