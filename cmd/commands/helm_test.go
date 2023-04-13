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
	"testing"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	kubemocks "github.com/argoproj-labs/argocd-autopilot/pkg/kube/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/chartutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1fake "k8s.io/client-go/kubernetes/fake"
)

func createFakeClientSet(namespace, name, key, value string) kubernetes.Interface {
	return v1fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		StringData: map[string]string{
			key: value,
		},
	})
}

func createMockKubeFactory(t *testing.T, namespace, name, key, value string) kube.Factory {
	ctrl := gomock.NewController(t)
	mockKube := kubemocks.NewMockFactory(ctrl)
	fakeCoreClient := createFakeClientSet(namespace, name, key, value)
	mockKube.EXPECT().KubernetesClientSet().Return(fakeCoreClient, nil)
	return mockKube
}

func Test_getUserToken(t *testing.T) {
	tests := map[string]struct {
		skip            bool
		namespace       string
		userTokenValues chartutil.Values
		want            string
		wantErr         string
		beforeFn        func(k *kubemocks.MockFactory)
		assertFn        func(t *testing.T, k *kubemocks.MockFactory)
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
			want: "some-token",
			beforeFn: func(k *kubemocks.MockFactory) {
				fakeCoreClient := v1fake.NewSimpleClientset(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "some-secret",
						Namespace: "some-namespace",
					},
					Data: map[string][]byte{
						"some-key": []byte("some-token"),
					},
				})
				k.EXPECT().KubernetesClientSet().Return(fakeCoreClient, nil)
			},
		},
		"should fail if no explicit token and secretKeyRef is nil": {
			userTokenValues: chartutil.Values{},
			wantErr:         "userToken must contain either a \"token\" field, or a \"secretKeyRef\"",
		},
		"should fail if no explicit token and secret is not found in cluster": {
			userTokenValues: chartutil.Values{
				"secretKeyRef": chartutil.Values{
					"name": "some-secret",
					"key":  "some-key",
				},
			},
			wantErr: "failed reading secret \"some-secret\": secrets \"some-secret\" not found",
			beforeFn: func(k *kubemocks.MockFactory) {
				fakeCoreClient := v1fake.NewSimpleClientset()
				k.EXPECT().KubernetesClientSet().Return(fakeCoreClient, nil)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var err error
			ctrl := gomock.NewController(t)
			mockKube := kubemocks.NewMockFactory(ctrl)
			if tt.beforeFn != nil {
				tt.beforeFn(mockKube)
			}

			opts := &HelmValidateValuesOptions{
				kubeFactory: mockKube,
				namespace:   tt.namespace,
			}
			got, err := getUserToken(context.Background(), opts, tt.userTokenValues)
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
