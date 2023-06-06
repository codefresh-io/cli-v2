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
	"os"
	"strings"
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

func Test_getUserToken(t *testing.T) {
	tests := map[string]struct {
		namespace string
		values    string
		clientSet kubernetes.Interface
		want      string
		wantErr   string
	}{
		"should return value from userToken.token field": {
			values: `
userToken:
  token: some-token`,
			want: "some-token",
		},
		"should return value from secretKeyRef data": {
			namespace: "some-namespace",
			values: `
userToken:
  secretKeyRef:
    name: some-secret
    key: some-key`,
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
			values: `
userToken: {}`,
			wantErr: "userToken must contain either a \"token\" field, or a \"secretKeyRef\"",
		},
		"should fail if no explicit token and secret does not exist": {
			values: `
userToken:
  secretKeyRef:
    name: some-secret
    key: some-key`,
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "failed getting user token from secretKeyRef: failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
		"should fail if no explicit token and secret does not contain key": {
			namespace: "some-namespace",
			values: `
userToken:
  secretKeyRef:
    name: some-secret
    key: some-key`,
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
			}),
			wantErr: "failed getting user token from secretKeyRef: secret \"some-secret\" does not contain key \"some-key\"",
		},
		"should fail if no explicit token and key contains empty string": {
			namespace: "some-namespace",
			values: `
userToken:
  secretKeyRef:
    name: some-secret
    key: some-key`,
			clientSet: v1fake.NewSimpleClientset(&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"some-key": []byte(""),
				},
			}),
			wantErr: "failed getting user token from secretKeyRef: secret \"some-secret\" key \"some-key\" is an empty string",
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
				namespace:   tt.namespace,
			}
			codefreshValues, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
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
		values     string
		clientSet  kubernetes.Interface
		accountId  string
		ingressUrl string
		wantErr    string
		beforeFn   func(t *testing.T, rt *gitmocks.MockRoundTripper)
	}{
		"should succeed if ingress values are valid": {
			values: `
global:
  runtime:
    ingress:
      enabled: true
      hosts:
      - some.host
      protocol: https
      className: some-ingressclass`,
			clientSet: v1fake.NewSimpleClientset(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-ingressclass",
				},
			}),
			beforeFn: func(t *testing.T, rt *gitmocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "HEAD", req.Method)
					assert.Equal(t, "https://some.host", req.URL.String())
					res := &http.Response{
						StatusCode: 200,
					}
					return res, nil
				})
			},
		},
		"should succeed if tunnel values are valid": {
			values: `
global:
  codefresh:
    accountId: some-account
  runtime:
    ingress:
      enabled: false
tunnel-client:
  enabled: true`,
		},
		"should succeed if using a manual ingress set-up": {
			values: `
global:
  runtime:
    ingress:
      enabled: false
    ingressUrl: https://some.host/path
tunnel-client:
  enabled: false`,
		},
		"should fail if no ingress values": {
			values: `
global:
  runtime: {}`,
			wantErr: "missing \"global.runtime.ingress\" values",
		},
		"should fail if no ingress.enabled value": {
			values: `
global:
  runtime:
    ingress: {}`,
			wantErr: "missing \"global.runtime.ingress.enabled\" value",
		},
		"should fail if ingress values are invalid": {
			values: `
global:
  runtime:
    ingress:
      enabled: true`,
			wantErr: "failed checking ingress data: \"global.runtime.ingress.hosts\" array must contain an array of strings",
		},
		"should fail if no tunnel-client.enabled value": {
			values: `
global:
  runtime:
    ingress:
      enabled: false
tunnel-client: {}`,
			wantErr: "missing \"tunnel-client.enabled\" value",
		},
		"should fail if no accountd for tunnel mode": {
			values: `
global:
  runtime:
    ingress:
      enabled: false
tunnel-client:
  enabled: true`,
			wantErr: "\"global.codefresh.accountId\" must be provided when using tunnel-client",
		},
		"should fail if no ingressUrl for manual mode": {
			values: `
global:
  runtime:
    ingress:
      enabled: false
tunnel-client:
  enabled: false`,
			wantErr: "must supply \"global.runtime.ingressUrl\" if both \"global.runtime.ingress.enabled\" and \"tunnel-client.enabled\" are false",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			ctrl := gomock.NewController(t)
			mockRT := gitmocks.NewMockRoundTripper(ctrl)
			if tt.clientSet != nil {
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			if tt.beforeFn != nil {
				tt.beforeFn(t, mockRT)
			}
			http.DefaultClient = &http.Client{
				Transport: mockRT,
			}
			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
			}
			values, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			err = checkIngress(context.Background(), opts, values)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_checkIngressDef(t *testing.T) {
	tests := map[string]struct {
		values    string
		clientSet kubernetes.Interface
		wantErr   string
		beforeFn  func(t *testing.T, rt *gitmocks.MockRoundTripper)
	}{
		"should succeed if values are valid": {
			values: `
hosts:
- some-host
protocol: https
className: some-ingressclass`,
			clientSet: v1fake.NewSimpleClientset(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-ingressclass",
				},
			}),
			beforeFn: func(t *testing.T, rt *gitmocks.MockRoundTripper) {
				rt.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "HEAD", req.Method)
					assert.Equal(t, "https://some-host", req.URL.String())
					res := &http.Response{
						StatusCode: 200,
					}
					return res, nil
				})
			},
		},
		"should succeed and skip http and k8s checks if skipValidation is set": {
			values: `
hosts:
- some-host
protocol: https
className: some-ingressclass
skipValidation: true`,
		},
		"should fail if there is no hosts array": {
			values: `
protocol: https
className: some-ingressclass
`,
			wantErr: "\"global.runtime.ingress.hosts\" array must contain an array of strings",
		},
		"should fail if hosts array is empty": {
			values: `
hosts: []
protocol: https
className: some-ingressclass`,
			wantErr: "\"global.runtime.ingress.hosts\" array must contain an array of strings",
		},
		"should fail if 1st host is not a string": {
			values: `
hosts:
- 123
protocol: https
className: some-ingressclass`,
			wantErr: "\"global.runtime.ingress.hosts\" values must be non-empty strings",
		},
		"shoulf fail if protocol is missing": {
			values: `
hosts:
- some-host
- second-host
className: some-ingressclass`,
			wantErr: "\"global.runtime.ingress.protocol\" value must be https|http",
		},
		"shoulf fail if protocol is not https|http": {
			values: `
hosts:
- some-host
- second-host
protocol: another-protocol
className: some-ingressclass`,
			wantErr: "\"global.runtime.ingress.protocol\" value must be https|http",
		},
		"should fail if HEAD request fails": {
			values: `
hosts:
- some-host
protocol: https
className: some-ingressclass`,
			clientSet: v1fake.NewSimpleClientset(&networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-ingressclass",
				},
			}),
			beforeFn: func(_ *testing.T, c *gitmocks.MockRoundTripper) {
				c.EXPECT().RoundTrip(gomock.AssignableToTypeOf(&http.Request{})).Return(nil, errors.New("some error"))
			},
			wantErr: "Head \"https://some-host\": some error",
		},
		"should fail if className is missing": {
			values: `
hosts:
- some-host
protocol: https`,
			wantErr: "\"global.runtime.ingress.className\" values must be a non-empty string",
		},
		"should fail if className is not found on cluster": {
			values: `
hosts:
- some-host
protocol: https
className: some-ingressclass`,
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "ingressclasses.networking.k8s.io \"some-ingressclass\" not found",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var mockKube *kubemocks.MockFactory
			ctrl := gomock.NewController(t)
			mockRT := gitmocks.NewMockRoundTripper(ctrl)
			if tt.clientSet != nil {
				mockKube = kubemocks.NewMockFactory(ctrl)
				mockKube.EXPECT().KubernetesClientSet().Return(tt.clientSet, nil)
			}

			if tt.beforeFn != nil {
				tt.beforeFn(t, mockRT)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
			}
			http.DefaultClient = &http.Client{
				Transport: mockRT,
			}
			ingressValues, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			err = checkIngressDef(context.Background(), opts, ingressValues)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_checkGit(t *testing.T) {
	tests := map[string]struct {
		values      string
		gitProvider platmodel.GitProviders
		gitApiUrl   string
		clientSet   kubernetes.Interface
		wantErr     string
		beforeFn    func(rt *gitmocks.MockRoundTripper)
	}{
		"should succeed if all values are correct": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password
      username: some-username`,
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
		"should succeed if there is no gitProvider data (skip token validation)": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password
      username: some-username`,
			gitProvider: "",
		},
		"should succeed if there is no gitApiUrl data (skip token validation)": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password
      username: some-username`,
			gitProvider: platmodel.GitProvidersGithub,
			gitApiUrl:   "",
		},
		"should skip validation if there are no gitCredentials values": {
			values: `
global:
  runtime: {}`,
		},
		"should skip validation if gitCredentials does not contain a password": {
			values: `
global:
  runtime:
    gitCredentials: {}`,
		},
		"should fail if failed to get git password": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        secretKeyRef:
          name: some-secret
          key: some-key
      username: some-username`,
			clientSet: v1fake.NewSimpleClientset(),
			wantErr:   "failed getting \"global.runtime.gitCredentials.password\": failed reading secret \"some-secret\": secrets \"some-secret\" not found",
		},
		"should fail if there is no git username": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password`,
			wantErr: "\"global.runtime.gitCredentials.username\" must be a non-empty string",
		},
		"should fail if account contains invalid gitProvider data": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password
      username: some-username`,
			gitProvider: "invalid-provider",
			gitApiUrl:   "some-api-url",
			wantErr:     "invalid gitProvider on account: provider \"invalid-provider\" is not a valid provider name",
		},
		"should fail if token is not valid": {
			values: `
global:
  runtime:
    gitCredentials:
      password:
        value: some-password
      username: some-username`,
			gitProvider: platmodel.GitProvidersGithub,
			gitApiUrl:   "some-api-url",
			wantErr:     "failed verifying runtime git token with git server \"some-api-url\": invalid git-token: Head \"some-api-url\": some error",
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
			mockRT := gitmocks.NewMockRoundTripper(ctrl)
			cfgit.GetProvider = func(_ cfgit.ProviderType, baseURL, _ string) (cfgit.Provider, error) {
				client := &http.Client{
					Transport: mockRT,
				}
				return cfgit.NewGithubProvider(baseURL, client)
			}
			if tt.beforeFn != nil {
				tt.beforeFn(mockRT)
			}

			gitValues, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			err = checkGit(context.Background(), opts, gitValues, tt.gitProvider, tt.gitApiUrl)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func Test_getGitCertFile(t *testing.T) {
	tests := map[string]struct {
		values    string
		gitApiUrl string
		want      string
		wantErr   string
	}{
		"should succeed if all values are correct": {
			values: `
argo-cd:
  configs:
    tls:
      certificates:
        some.host: some-cert`,
			gitApiUrl: "https://some.host/org/repo.git",
			want:      "some.host.cer",
		},
		"should return empty string if no certificates in argo-cd values": {
			want: "",
		},
		"should return empty string if certificates do not contain gitApiUrl hostname": {
			values: `
argo-cd:
  configs:
    tls:
      certificates:
        another.host: some-cert`,
			gitApiUrl: "https://some.host/org/repo.git",
			want:      "",
		},
		"should return empty string if certificates is empty in values": {
			values: `
argo-cd:
  configs:
    tls:
      certificates:
        some.host: ""`,
			gitApiUrl: "https://some.host/org/repo.git",
			want:      "",
		},
		"should fail if gitApiUrl is invalid": {
			values: `
argo-cd:
  configs:
    tls:
      certificates:
        another.host: some-cert`,
			gitApiUrl: "https://so:me.host/org/repo.git",
			wantErr:   "failed parsing gitApiUrl \"https://so:me.host/org/repo.git\": parse \"https://so:me.host/org/repo.git\": invalid port \":me.host\" after host",
		},
		"should fail if certificate is not a string": {
			values: `
argo-cd:
  configs:
    tls:
      certificates:
        some.host: 123`,
			gitApiUrl: "https://some.host/org/repo.git",
			wantErr:   "certificate for git server \"some.host\" must be a string value",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			values, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			got, err := getGitCertFile(context.Background(), values, tt.gitApiUrl)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if got != "" {
				defer os.Remove(got)
			}

			if !strings.HasSuffix(got, tt.want) {
				t.Errorf("getGitCertFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getGitPassword(t *testing.T) {
	tests := map[string]struct {
		values    string
		clientSet kubernetes.Interface
		want      string
		wantErr   string
	}{
		"should return password from the value field": {
			values: `
password:
  value: some-password`,
			want: "some-password",
		},
		"should return nothing if there is no value or secretKeyRef": {
			values: `
password: {}`,
			want: "",
		},
		"should return value from secretKeyRef, if there is no explicit value": {
			values: `
password:
  secretKeyRef:
    name: some-secret
    key: some-key`,
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
			values: `
password:
  secretKeyRef:
    name: some-secret
    key: some-key`,
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
			gitValues, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			got, err := getGitPassword(context.Background(), opts, gitValues)
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
		values    string
		clientSet kubernetes.Interface
		want      string
		wantErr   string
	}{
		"should succeed if all values exist": {
			values: `
name: some-secret
key: some-key`,
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
		"should return an empty string if name field is missing": {
			values: `
key: some-key`,
			want: "",
		},
		"should return an empty string if key field is missing": {
			values: `
name: some-secret`,
			want: "",
		},
		"should fail if secret not found": {
			values: `
name: some-secret
key: some-key`,
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
			secretKeyRef, err := chartutil.ReadValues([]byte(tt.values))
			if err != nil {
				assert.Fail(t, err.Error())
				return
			}

			got, err := getValueFromSecretKeyRef(context.Background(), opts, secretKeyRef)
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
