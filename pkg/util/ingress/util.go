// Copyright 2021 The Codefresh Authors.
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

package util

import (
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	IngressPath struct {
		Path        string
		PathType v1.PathType
		ServiceName string
		ServicePort int32
	}

	CreateIngressOptions struct {
		Name        string
		Namespace   string
		Host        string
		//Path        string
		//ServiceName string
		//ServicePort int32
		Paths []IngressPath
	}
)

func createHTTPIngressPaths(paths []IngressPath) []v1.HTTPIngressPath {
	httpIngressPaths := make([]v1.HTTPIngressPath, len(paths))
	for _, p := range paths {
		pathType := v1.PathTypePrefix // default
		if p.PathType != "" {
			pathType = p.PathType
		}

		httpIngressPaths = append(httpIngressPaths, v1.HTTPIngressPath{
				Path:     p.Path,
				PathType: &pathType,
				Backend: v1.IngressBackend{
					Service: &v1.IngressServiceBackend{
						Name: p.ServiceName,
						Port: v1.ServiceBackendPort{
							Number: p.ServicePort,
						},
					},
				},
			})
	}

	return httpIngressPaths
}

func CreateIngress(opts *CreateIngressOptions) *v1.Ingress {
	return &v1.Ingress{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "Ingress",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "traefik",
				//"nginx.ingress.kubernetes.io/rewrite-target":   "/$2",
				//"nginx.ingress.kubernetes.io/backend-protocol": "https",
			},
		},
		Spec: v1.IngressSpec{
			Rules: []v1.IngressRule{
				{
					Host: opts.Host,
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: createHTTPIngressPaths(opts.Paths),
							//Paths: []v1.HTTPIngressPath{
							//	{
							//		Path:     fmt.Sprintf("/%s(/|$)(.*)", opts.Path),
							//		PathType: &pathType,
							//		Backend: v1.IngressBackend{
							//			Service: &v1.IngressServiceBackend{
							//				Name: opts.ServiceName,
							//				Port: v1.ServiceBackendPort{
							//					Number: opts.ServicePort,
							//				},
							//			},
							//		},
							//	},
							//},
						},
					},
				},
			},
		},
	}
}
