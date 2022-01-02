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
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	IngressPath struct {
		Path        string
		PathType    netv1.PathType
		ServiceName string
		ServicePort int32
	}

	CreateIngressOptions struct {
		Name        string
		Namespace   string
		Annotations map[string]string
		Host        string
		Paths       []IngressPath
	}
)

func createHTTPIngressPaths(paths []IngressPath) []netv1.HTTPIngressPath {
	httpIngressPaths := make([]netv1.HTTPIngressPath, 0, len(paths))
	for _, p := range paths {
		httpIngressPaths = append(httpIngressPaths, netv1.HTTPIngressPath{
			Path:     p.Path,
			PathType: &p.PathType,
			Backend: netv1.IngressBackend{
				Service: &netv1.IngressServiceBackend{
					Name: p.ServiceName,
					Port: netv1.ServiceBackendPort{
						Number: p.ServicePort,
					},
				},
			},
		})
	}

	return httpIngressPaths
}

func CreateIngress(opts *CreateIngressOptions) *netv1.Ingress {
	ingress := &netv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			APIVersion: netv1.SchemeGroupVersion.String(),
			Kind:       "Ingress",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					Host: opts.Host,
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: createHTTPIngressPaths(opts.Paths),
						},
					},
				},
			},
		},
	}

	if opts.Annotations != nil {
		ingress.ObjectMeta.Annotations = opts.Annotations
	}

	return ingress
}
