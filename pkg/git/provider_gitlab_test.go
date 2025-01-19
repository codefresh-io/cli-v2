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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codefresh-io/cli-v2/pkg/git/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func newGitlab(transport http.RoundTripper) *gitlab {
	client := &http.Client{
		Transport: transport,
	}
	g, _ := NewGitlabProvider("https://some.server", client)
	return g.(*gitlab)
}

func TestNewGitlabProvider(t *testing.T) {
	tests := map[string]struct {
		baseURL    string
		wantApiURL string
		wantCloud  bool
		wantErr    string
	}{
		"should use standard api path when base is cloud host": {
			baseURL:    "https://gitlab.com",
			wantApiURL: "https://gitlab.com/api/v4",
			wantCloud:  true,
		},
		"should use standard api path when base is cloud host with path": {
			baseURL:    "https://gitlab.com/org/repo",
			wantApiURL: "https://gitlab.com/api/v4",
			wantCloud:  true,
		},
		"should use standard api path when base is host only": {
			baseURL:    "https://some.server",
			wantApiURL: "https://some.server/api/v4",
			wantCloud:  false,
		},
		"should use baseUrl as apiUrl if it on-prem and has path": {
			baseURL:    "https://some.server/some/api/v-whatever",
			wantApiURL: "https://some.server/some/api/v-whatever",
			wantCloud:  false,
		},
		"should fail when base is not a valid url": {
			baseURL: "https://contains-bad-\x7f",
			wantErr: "parse \"https://contains-bad-\\x7f\": net/url: invalid control character in URL",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewGitlabProvider(tt.baseURL, &http.Client{})
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantApiURL, got.ApiURL())
			assert.Equal(t, tt.wantCloud, got.IsCloud())
		})
	}
}

func Test_gitlab_checkApiScope(t *testing.T) {
	tests := map[string]struct {
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if POST projects fails": {
			wantErr: "failed checking api scope: Post \"https://some.server/api/v4/projects\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "GET", req.Method)
					assert.Equal(t, "https://some.server/api/v4/user", req.URL.String())
					body, _ := json.Marshal(&gitlabUserResponse{
						Username: "username",
						Bot:      false,
					})
					bodyReader := io.NopCloser(strings.NewReader(string(body[:])))
					res := &http.Response{
						StatusCode: 200,
						Body:       bodyReader,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if GET user fails": {
			wantErr: "failed checking api scope: failed getting user: Get \"https://some.server/api/v4/user\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if POST fails with 403": {
			wantErr: "git-token is invalid or missing required \"api\" scope",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "GET", req.Method)
					assert.Equal(t, "https://some.server/api/v4/user", req.URL.String())
					body, _ := json.Marshal(&gitlabUserResponse{
						Username: "username",
						Bot:      false,
					})
					bodyReader := io.NopCloser(strings.NewReader(string(body[:])))
					res := &http.Response{
						StatusCode: 200,
						Body:       bodyReader,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(&http.Response{
					StatusCode: http.StatusForbidden,
				}, nil)
			},
		},
		"Should succeed if POST returns 400": {
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "GET", req.Method)
					assert.Equal(t, "https://some.server/api/v4/user", req.URL.String())
					body, _ := json.Marshal(&gitlabUserResponse{
						Username: "username",
						Bot:      false,
					})
					bodyReader := io.NopCloser(strings.NewReader(string(body[:])))
					res := &http.Response{
						StatusCode: 200,
						Body:       bodyReader,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "POST", req.Method)
					assert.Equal(t, "https://some.server/api/v4/projects", req.URL.String())
					res := &http.Response{
						StatusCode: http.StatusBadRequest,
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
			g := newGitlab(mockTransport)
			err := g.checkApiScope(context.Background(), "token")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_gitlab_checkReadRepositoryScope(t *testing.T) {
	tests := map[string]struct {
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if HEAD fails": {
			wantErr: "failed checking read_repository scope: Head \"https://some.server/api/v4/projects\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if HEAD returns 403": {
			wantErr: "personal-git-token is invalid or missing required \"read_api\" or \"read_repository\" scope",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(&http.Response{
					StatusCode: http.StatusForbidden,
				}, nil)
			},
		},
		"Should succeed if HEAD returns 200": {
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "HEAD", req.Method)
					assert.Equal(t, "https://some.server/api/v4/projects", req.URL.String())
					res := &http.Response{
						StatusCode: http.StatusOK,
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
			g := newGitlab(mockTransport)
			err := g.checkReadRepositoryScope(context.Background(), "token")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
