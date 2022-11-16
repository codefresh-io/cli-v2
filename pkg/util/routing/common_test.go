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

package routing_test

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/codefresh-io/cli-v2/pkg/util/routing"
	v1 "k8s.io/api/networking/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
)

// TestCreateInternalRouterRoute calls routing.CreateInternalRouterRoute, checking
// that a correct route is returned.
func TestCreateInternalRouterRoute(t *testing.T) {
	tests := map[string]struct {
		routeOpts    *routing.CreateRouteOpts
		wantFilePath string
		getExpected  func() interface{}
	}{
		string(routing.IngressControllerALB): {
			routeOpts: &routing.CreateRouteOpts{
				RuntimeName:       "test-runtime",
				Namespace:         "test-runtime",
				IngressClass:      "alb",
				Hostname:          "testing.foo.bar.com",
				IngressController: routing.GetIngressController(string(routing.IngressControllerALB)),
				Annotations:       nil,
				GatewayName:       "",
				GatewayNamespace:  "",
			},
			getExpected: func() interface{} {
				ingress, err := yamlToIngress("testdata/alb-ingress.yaml")
				if err != nil {
					log.Fatal(err)
				}

				return ingress
			},
		},
		string(routing.IngressControllerNginxCommunity): {
			routeOpts: &routing.CreateRouteOpts{
				RuntimeName:       "test-runtime",
				Namespace:         "test-runtime",
				IngressClass:      "nginx",
				Hostname:          "testing.foo.bar.com",
				IngressController: routing.GetIngressController(string(routing.IngressControllerNginxCommunity)),
				Annotations:       nil,
				GatewayName:       "",
				GatewayNamespace:  "",
			},
			getExpected: func() interface{} {
				ingress, err := yamlToIngress("testdata/nginx-ingress.yaml")
				if err != nil {
					log.Fatal(err)
				}

				return ingress
			},
		},
	}

	for tname, tt := range tests {
		t.Run(tname, func(t *testing.T) {
			_, received := routing.CreateInternalRouterRoute(tt.routeOpts, false, true, false)
			assert.Equal(t, tt.getExpected(), received)
		})
	}
}

func yamlToIngress(path string) (*v1.Ingress, error) {
	var want *v1.Ingress
	ingressFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	d := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(ingressFile), 100)
	err = d.Decode(&want)
	if err != nil {
		return nil, err
	}

	return want, nil
}
