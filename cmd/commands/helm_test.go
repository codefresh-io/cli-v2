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

package commands

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	gitmocks "github.com/codefresh-io/cli-v2/pkg/git/mocks"

	kubemocks "github.com/argoproj-labs/argocd-autopilot/pkg/kube/mocks"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/chartutil"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1fake "k8s.io/client-go/kubernetes/fake"
)

func generateAccount(name string, gitProvider platmodel.GitProviders, gitApiUrl string) *platmodel.Account {
	return &platmodel.Account{
		Name:        &name,
		GitProvider: &gitProvider,
		GitAPIURL:   &gitApiUrl,
	}
}

func Test_getUserToken(t *testing.T) {
	tests := map[string]struct {
		run             bool
		namespace       string
		userTokenValues chartutil.Values
		clientSet       kubernetes.Interface
		want            string
		wantErr         string
	}{
		"should return value from userToken.token field": {
			userTokenValues: chartutil.Values{
				"token": "some-token",
			},
			want: "some-token",
		},
		"should return value from secretKeyRef data": {
			namespace: "some-namespace",
			userTokenValues: chartutil.Values{
				"secretKeyRef": chartutil.Values{
					"name": "some-secret",
					"key":  "some-key",
				},
			},
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"some-key": []byte("some-token"),
				},
			}),
			want: "some-token",
		},
		"should fail if no explicit token and secretKeyRef is nil": {
			userTokenValues: chartutil.Values{},
			wantErr:         "userToken must contain either a \"token\" field, or a \"secretKeyRef\"",
		},
		"should fail if no explicit token and getValueFromSecretKeyRef fails": {
			run: true,
			userTokenValues: chartutil.Values{
				"secretKeyRef": chartutil.Values{
					"name": "some-secret",
					"key":  "some-key",
				},
			},
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "Failed getting user token from secretKeyRef: failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
		"should fail if no explicit token and secret does not contain key": {
			namespace: "some-namespace",
			userTokenValues: chartutil.Values{
				"secretKeyRef": chartutil.Values{
					"name": "some-secret",
					"key":  "some-key",
				},
			},
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
			}),
			wantErr: "Failed getting user token from secretKeyRef: secret \"some-secret\" does not contain key \"some-key\"",
		},
		"should fail if no explicit token and key contains empty string": {
			namespace: "some-namespace",
			userTokenValues: chartutil.Values{
				"secretKeyRef": chartutil.Values{
					"name": "some-secret",
					"key":  "some-key",
				},
			},
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"some-key": []byte(""),
				},
			}),
			wantErr: "Failed getting user token from secretKeyRef: secret \"some-secret\" key \"some-key\" is an empty string",
		},
	}
	for name, tt := range tests {
		// if !tt.run {
		// 	continue
		// }
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			if tt.clientSet != nil {
				ctrl := gomock.NewController(t)
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
				namespace:   tt.namespace,
			}
			codefreshValues := chartutil.Values{
				"userToken": tt.userTokenValues,
			}
			got, err := getUserToken(context.Background(), opts, codefreshValues)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("getUserToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkIngress(t *testing.T) {
	tests := map[string]struct {
		ingress   chartutil.Values
		clientSet kubernetes.Interface
		wantErr   string
		beforeFn  func(t *testing.T, c *gitmocks.MockRoundTripper)
	}{
		"should succeed if values are valid": {
			ingress: chartutil.Values{
				"hosts": []interface{}{
					"some-host",
					"second-host",
				},
				"protocol":  "https",
				"className": "some-ingressclass",
			},
			clientSet: v1fake.NewSimpleClientset(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-ingressclass",
				},
			}),
			beforeFn: func(t *testing.T, c *gitmocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "HEAD", req.Method)
					assert.Equal(t, "https://some-host", req.URL.String())
					res := &http.Response{
						StatusCode: 200,
					}
					return res, nil
				})
			},
		},
		"should fail if there is no hosts array": {
			ingress: chartutil.Values{},
			wantErr: "\"global.runtime.ingress.hosts\" array must contain an array of strings",
		},
		"should fail if hosts array is empty": {
			ingress: chartutil.Values{
				"hosts": []interface{}{},
			},
			wantErr: "\"global.runtime.ingress.hosts\" array must contain values",
		},
		"should fail if 1st host is not a string": {
			ingress: chartutil.Values{
				"hosts": []interface{}{123},
			},
			wantErr: "\"global.runtime.ingress.hosts\" values must be non-empty strings",
		},
		"shoulf fail if protocol is missing": {
			ingress: chartutil.Values{
				"hosts": []interface{}{"some-host"},
			},
			wantErr: "\"global.runtime.ingress.protocol\" value must be https|http",
		},
		"shoulf fail if protocol is not https|http": {
			ingress: chartutil.Values{
				"hosts":    []interface{}{"some-host"},
				"protocol": "another-protocol",
			},
			wantErr: "\"global.runtime.ingress.protocol\" value must be https|http",
		},
		"should fail if HEAD to host[0] fails": {
			ingress: chartutil.Values{
				"hosts":    []interface{}{"some-host"},
				"protocol": "https",
			},
			wantErr: "Head \"https://some-host\": some error",
			beforeFn: func(_ *testing.T, c *gitmocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
		},
		"should fail if className is missing": {
			ingress: chartutil.Values{
				"hosts":    []interface{}{"some-host"},
				"protocol": "https",
			},
			wantErr: "\"global.runtime.ingress.className\" values must be a non-empty string",
			beforeFn: func(_ *testing.T, c *gitmocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
		"should fail if className is not found on cluster": {
			ingress: chartutil.Values{
				"hosts":     []interface{}{"some-host"},
				"protocol":  "https",
				"className": "some-ingressclass",
			},
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "ingressclasses.networking.k8s.io \"some-ingressclass\" not found",
			beforeFn: func(_ *testing.T, c *gitmocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(&http.Response{
					StatusCode: 200,
				}, nil)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			ctrl := gomock.NewController(t)
			mockTransport := gitmocks.NewMockRoundTripper(ctrl)
			if tt.clientSet != nil {
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			if tt.beforeFn != nil {
				tt.beforeFn(t, mockTransport)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
			}
			http.DefaultClient = &http.Client{
				Transport: mockTransport,
			}
			err := checkIngressDef(context.Background(), opts, tt.ingress)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
		})
	}
}

func Test_checkGitCredentials(t *testing.T) {
	tests := map[string]struct {
		git         chartutil.Values
		gitProvider platmodel.GitProviders
		gitApiUrl   string
		clientSet   kubernetes.Interface
		wantErr     string
		beforeFn    func(rt *gitmocks.MockRoundTripper)
	}{
		"should succeed if all values are correct": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
				"username": "some-username",
			},
			gitProvider: platmodel.GitProvidersGithub,
			gitApiUrl:   "some-api-url",
			beforeFn: func(rt *gitmocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).DoAndReturn(func(_ *http.Request) (*http.Response, error) {
					header := http.Header{}
					header.Add("X-Oauth-Scopes", "repo, admin:repo_hook")
					res := &http.Response{
						StatusCode: 200,
						Header:     header,
					}
					return res, nil
				})
			},
		},
		"should succeed if there is no git password at all (skip-check)": {
			git: chartutil.Values{},
		},
		"should fail if faied to get git password": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"secretKeyRef": chartutil.Values{
						"name": "some-secret",
						"key":  "some-key",
					},
				},
				"username": "some-username",
			},
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "failed getting \"global.runtime.gitCredentials.password\": failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
		"should fail if there is no git username": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
			},
			wantErr: "\"global.runtime.gitCredentials.username\" must be a non-empty string",
		},
		"should fail if account doesn't have gitProvider data": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
				"username": "some-username",
			},
			gitProvider: "",
			gitApiUrl:   "some-api-url",
			wantErr:     "account \"some-account\" is missing gitProvider data",
		},
		"should fail if account doesn't have gitApiUrl data": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
				"username": "some-username",
			},
			gitProvider: platmodel.GitProvidersGithub,
			gitApiUrl:   "",
			wantErr:     "account \"some-account\" is missing gitApiUrl data",
		},
		"should fail if account contains invalid gitProvider data": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
				"username": "some-username",
			},
			gitProvider: "invalid-provider",
			gitApiUrl:   "some-api-url",
			wantErr:     "invalid gitProvider on account: provider \"invalid-provider\" is not a valid provider name",
		},
		"should fail if token is not valid": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
				"username": "some-username",
			},
			gitProvider: platmodel.GitProvidersGithub,
			gitApiUrl:   "some-api-url",
			wantErr:     "git-token invalid: Head \"some-api-url\": some error",
			beforeFn: func(rt *gitmocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Times(1).Return(nil, errors.New("some error"))
			},
		},
	}
	orgGetProvider := cfgit.GetProvider
	defer func() { cfgit.GetProvider = orgGetProvider }()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			ctrl := gomock.NewController(t)
			if tt.clientSet != nil {
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
				namespace:   "some-namespace",
			}
			rt := gitmocks.NewMockRoundTripper(ctrl)
			cfgit.GetProvider = func(_ cfgit.ProviderType, baseURL, _ string) (cfgit.Provider, error) {
				client := &http.Client{
					Transport: rt,
				}
				return cfgit.NewGithubProvider(baseURL, client)
			}
			if tt.beforeFn != nil {
				tt.beforeFn(rt)
			}

			err := checkGit(context.Background(), opts, tt.git, tt.gitProvider, tt.gitApiUrl)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_getGitPassword(t *testing.T) {
	tests := map[string]struct {
		git       chartutil.Values
		clientSet kubernetes.Interface
		want      string
		wantErr   string
	}{
		"should return password from the value field": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"value": "some-password",
				},
			},
			want: "some-password",
		},
		"should return nothing if there is no value or secretKeyRef": {
			git:  chartutil.Values{},
			want: "",
		},
		"should return value from secretKeyRef, if there is no explicit value": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"secretKeyRef": chartutil.Values{
						"name": "some-secret",
						"key":  "some-key",
					},
				},
			},
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"some-key": []byte("some-token"),
				},
			}),
			want: "some-token",
		},
		"should fail if no explicit value, and secretKeyRef fails": {
			git: chartutil.Values{
				"password": chartutil.Values{
					"secretKeyRef": chartutil.Values{
						"name": "some-secret",
						"key":  "some-key",
					},
				},
			},
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			if tt.clientSet != nil {
				ctrl := gomock.NewController(t)
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
				namespace:   "some-namespace",
			}

			got, err := getGitPassword(context.Background(), opts, tt.git)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("getGitPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getValueFromSecretKeyRef(t *testing.T) {
	tests := map[string]struct {
		secretKeyRef chartutil.Values
		clientSet    kubernetes.Interface
		want         string
		wantErr      string
	}{
		"should succeed if all values exist": {
			secretKeyRef: chartutil.Values{
				"name": "some-secret",
				"key":  "some-key",
			},
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"some-key": []byte("some-token"),
				},
			}),
			want: "some-token",
		},
		"should fail if name field is missing": {
			secretKeyRef: chartutil.Values{},
			wantErr:      "\"secretKeyRef.name\" must be a non-empty string",
		},
		"should fail if key field is missing": {
			secretKeyRef: chartutil.Values{
				"name": "some-secret",
			},
			wantErr: "\"secretKeyRef.key\" must be a non-empty string",
		},
		"should fail if secret not found": {
			secretKeyRef: chartutil.Values{
				"name": "some-secret",
				"key":  "some-key",
			},
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			if tt.clientSet != nil {
				ctrl := gomock.NewController(t)
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
				namespace:   "some-namespace",
			}

			got, err := getValueFromSecretKeyRef(context.Background(), opts, tt.secretKeyRef)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("getValueFromSecretKeyRef() = %v, want %v", got, tt.want)
			}
		})
	}
}
