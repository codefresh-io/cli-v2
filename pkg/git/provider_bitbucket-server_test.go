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

func newBitbucketServer(transport http.RoundTripper) *bitbucketServer {
	client := &http.Client{
		Transport: transport,
	}
	bbs, _ := NewBitbucketServerProvider("https://some.server", client)
	return bbs.(*bitbucketServer)
}

func TestNewBitbucketServerProvider(t *testing.T) {
	tests := map[string]struct {
		baseURL    string
		wantApiURL string
		wantErr    string
	}{
		"should use standard api path when base is host only": {
			baseURL: "https://some.server",
			wantApiURL: "https://some.server/rest/api/1.0",
		},
		"should use baseUrl as apiUrl if it has path": {
			baseURL: "https://some.server/some/api/v-whatever",
			wantApiURL: "https://some.server/some/api/v-whatever",
		},
		"should fail when base is not a valid url": {
			baseURL: "https://contains-bad-\x7f",
			wantErr: "parse \"https://contains-bad-\\x7f\": net/url: invalid control character in URL",
		},
		"should fail if base is in bitbucket-cloud": {
			baseURL: "https://bitbucket.org",
			wantErr: "wrong domain for bitbucket-server provider: \"https://bitbucket.org\"\n  maybe you meant to use \"bitbucket\" for the cloud git provider?",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewBitbucketServerProvider(tt.baseURL, &http.Client{})
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantApiURL, got.ApiURL())
			assert.False(t, got.IsCloud())
		})
	}
}

func Test_bitbucketServer_checkProjectAdminPermission(t *testing.T) {
	tests := map[string]struct {
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if get current username fails": {
			wantErr: "failed checking Project admin permission: failed getting current user: Head \"https://some.server/rest/api/1.0/application-properties\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if token is invalid": {
			wantErr: "failed checking Project admin permission: invalid token",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
		"Should fail if POST fails": {
			wantErr: "failed checking Project admin permission: Post \"https://some.server/rest/api/1.0/users/username/repos\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				callFirst := c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-AUSERNAME", "username")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(nil, errors.New("some error")).After(callFirst)
			},
		},
		"Should fail if POST returns 401": {
			wantErr: "git-token is invalid or missing required \"Project admin\" scope",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				callFirst := c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-AUSERNAME", "username")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(&http.Response{
					StatusCode: http.StatusUnauthorized,
				}, nil).After(callFirst)
			},
		},
		"Should succeed if POST returns 400": {
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				callFirst := c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-AUSERNAME", "username")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "POST", req.Method)
					assert.Equal(t, "https://some.server/rest/api/1.0/users/username/repos", req.URL.String())
					res := &http.Response{
						StatusCode: http.StatusBadRequest,
					}
					return res, nil
				}).After(callFirst)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockTransport := mocks.NewMockRoundTripper(ctrl)
			tt.beforeFn(t, mockTransport)
			bbs := newBitbucketServer(mockTransport)
			err := bbs.checkProjectAdminPermission(context.Background(), "token")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_bitbucketServer_checkRepoReadPermission(t *testing.T) {
	tests := map[string]struct {
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if get current username fails": {
			wantErr: "failed checking Repo read permission: failed getting current user: Head \"https://some.server/rest/api/1.0/application-properties\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if token is invalid": {
			wantErr: "failed checking Repo read permission: invalid token",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
		"Should succeed if there is a username": {
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-AUSERNAME", "username")
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
			bbs := newBitbucketServer(mockTransport)
			err := bbs.checkRepoReadPermission(context.Background(), "token")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_bitbucketServer_getCurrentUsername(t *testing.T) {
	tests := map[string]struct {
		want     string
		wantErr  string
		beforeFn func(t *testing.T, c *mocks.MockRoundTripper)
	}{
		"Should fail if request fails": {
			wantErr: "failed getting current user: Head \"https://some.server/rest/api/1.0/application-properties\": some error",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(nil, errors.New("some error"))
			},
		},
		"Should fail if res header is missing": {
			wantErr: "invalid token",
			beforeFn: func(_ *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
		"Should succeed when value is in the res header": {
			want: "username",
			beforeFn: func(t *testing.T, c *mocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "HEAD", req.Method)
					assert.Equal(t, "https://some.server/rest/api/1.0/application-properties", req.URL.String())
					header := http.Header{}
					header.Add("X-AUSERNAME", "username")
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
			bbs := newBitbucketServer(mockTransport)
			got, err := bbs.getCurrentUsername(context.Background(), "token")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
