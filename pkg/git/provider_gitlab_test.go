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

func newGitlab(transport http.RoundTripper) *gitlab {
	client := &http.Client{
		Transport: transport,
	}
	g, _ := NewGitlabProvider("https://some.server", client)
	return g.(*gitlab)
}

func Test_gitlab_checkApiScope(t *testing.T) {
	tests := map[string]struct {
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if POST fails": {
			wantErr: "failed checking api scope: Post \"https://some.server/api/v4/projects\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if POST fails with 403": {
			wantErr: "git-token is invalid or missing required \"api\" scope",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(&http.Response{
					StatusCode: http.StatusForbidden,
				}, nil)
			},
		},
		"Should succeed if POST returns 400": {
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
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
