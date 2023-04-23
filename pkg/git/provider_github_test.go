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

func newGithub(transport http.RoundTripper) *github {
	client := &http.Client{
		Transport: transport,
	}
	g, _ := NewGithubProvider("https://some.server", client)
	return g.(*github)
}

func TestNewGithubProvider(t *testing.T) {
	tests := map[string]struct {
		baseUrl    string
		wantApiUrl string
		wantErr    string
	}{
		"should use cloud api path when base is cloud host": {
			baseUrl:    "https://github.com",
			wantApiUrl: "https://api.github.com",
		},
		"should use cloud api path when base is cloud host with path": {
			baseUrl:    "https://github.com/org/repo",
			wantApiUrl: "https://api.github.com",
		},
		"should use standard api path when base is host only": {
			baseUrl:    "https://some.server",
			wantApiUrl: "https://some.server/api/v3",
		},
		"should use baseUrl as apiUrl if it on-prem and has path": {
			baseUrl:    "https://some.server/some/api/v-whatever",
			wantApiUrl: "https://some.server/some/api/v-whatever",
		},
		"should fail when base is not a valid url": {
			baseUrl: "https://contains-bad-\x7f",
			wantErr: "parse \"https://contains-bad-\\x7f\": net/url: invalid control character in URL",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewGithubProvider(tt.baseUrl, &http.Client{})
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantApiUrl, got.ApiURL())
		})
	}
}

func Test_github_verifyToken(t *testing.T) {
	tests := map[string]struct {
		requiredScopes []string
		wantErr        string
		beforeFn       func(rt *mocks.MockRoundTripper)
	}{
		"Should fail if HEAD fails": {
			wantErr: "Head \"https://some.server/api/v3\": some error",
			beforeFn: func(rt *mocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if no X-Oauth-Scopes in res headers": {
			wantErr: "missing scopes header on response",
			beforeFn: func(rt *mocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
		"Should fail if required scope is not in res header": {
			requiredScopes: []string{"scope 3"},
			wantErr:        "the provided token is missing one or more of the required scopes: scope 3",
			beforeFn: func(rt *mocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
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
		"Should succeed if all required scopes are in the res header": {
			requiredScopes: []string{"scope 3", "scope 4"},
			beforeFn: func(rt *mocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-Oauth-Scopes", "scope 1, scope 2, scope 3, scope 4")
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
			tt.beforeFn(mockTransport)
			g := newGithub(mockTransport)
			err := g.verifyToken(context.Background(), "token", tt.requiredScopes)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
