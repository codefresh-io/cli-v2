// Copyright 2024 The Codefresh Authors.
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

package routing

import (
	v1 "github.com/projectcontour/contour/apis/projectcontour/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type HTTPProxyRoute struct {
	Path        string
	PathType    string
	ServiceName string
	ServicePort int32
}

func createHTTPProxy(opts *CreateRouteOpts) *v1.HTTPProxy {
	httpProxy := &v1.HTTPProxy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "HTTPProxy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
		},
		Spec: v1.HTTPProxySpec{
			VirtualHost: &v1.VirtualHost{
				Fqdn: opts.Hostname,
			},
			Routes: createHTTPProxyRoutes(opts.Paths),
		},
	}

	if opts.Annotations != nil {
		httpProxy.ObjectMeta.Annotations = opts.Annotations
	}

	return httpProxy
}

func createHTTPProxyRoutes(paths []RoutePath) []v1.Route {
	var httpProxyRoutes []v1.Route
	for _, p := range paths {
		httpProxyRoutes = append(httpProxyRoutes, v1.Route{
			Conditions: []v1.MatchCondition{
				{
					Prefix: p.path,
				},
			},
			Services: []v1.Service{
				{
					Name: p.serviceName,
					Port: int(p.servicePort),
				},
			},
			EnableWebsockets: true,
		})
	}

	return httpProxyRoutes
}
