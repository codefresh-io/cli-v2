// Copyright 2023 The Codefresh Authors.
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
	"net/http"
	"testing"

	"github.com/codefresh-io/cli-v2/pkg/git/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func newBitbucket(transport http.RoundTripper) *bitbucket {
	client := &http.Client{
		Transport: transport,
	}
	g, _ := NewBitbucketProvider("https://some.server", client)
	return g.(*bitbucket)
}

func Test_bitbucket_verifyToken(t *testing.T) {
	tests := map[string]struct {
		requiredScopes [][]string
		wantErr        string
		beforeFn       func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if HEAD fails": {
			wantErr: "failed checking token scope permission: failed getting current user: Head \"https://some.server/api/2.0/user\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if no x-oauth-Scopes in res headers": {
			wantErr: "failed checking token scope permission: invalid token",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				header := http.Header{}
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
					Header:     header,
				}, nil)
			},
		},
		"Should fail if required scope is not in res header": {
			requiredScopes: [][]string{{"scope 3"}},
			wantErr:        "the provided token is missing required token scopes, got: scope 1, scope 2 \nrequired: scope 3",
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-Oauth-Scopes", "scope 1, scope 2")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
			},
		},
		"Should succeed if all required scopes or higher are in the res header": {
			requiredScopes: [][]string{
				{"scope 3:write", "scope 3:admin"},
				{"scope 4"},
			},
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-Oauth-Scopes", "scope 1, scope 2, scope 3:write, scope 4")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockTransport := mocks.NewMockRoundTripper(ctrl)
			tt.beforeFn(t, mockTransport)
			g := newBitbucket(mockTransport)
			err := g.verifyToken(context.Background(), "token", "username", tt.requiredScopes)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
