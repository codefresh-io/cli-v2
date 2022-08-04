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
	"net/url"

	"github.com/codefresh-io/cli-v2/pkg/log"
)

type (
	bitbucketServer struct {
		providerType ProviderType
		apiURL       *url.URL
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
		apiURL:      u,
	}, nil
}

func (bbs *bitbucketServer) Type() ProviderType {
	return bbs.providerType
}

func (bbs *bitbucketServer) BaseURL() string {
	urlClone := *bbs.apiURL
	urlClone.Path = ""
	urlClone.RawQuery = ""
	return urlClone.String()
}

func (bbs *bitbucketServer) VerifyToken(ctx context.Context, tokenType TokenType, token string) error {
	log.G(ctx).Debug("Skip verifying token for bitbucket, to be implemented later")
	return nil
}

func (bbs *bitbucketServer) SupportsMarketplace() bool {
	return false
}
