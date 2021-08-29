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
	"fmt"

	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	CreateIngressOptions struct {
		Name        string
		Namespace   string
		Host        string
		Path        string
		ServiceName string
		ServicePort int32
	}
)

func CreateIngress(opts *CreateIngressOptions) *v1.Ingress {
	pathType := v1.PathTypePrefix
	return &v1.Ingress{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "Ingress",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "nginx",
				"nginx.ingress.kubernetes.io/rewrite-target":   "/$2",
				"nginx.ingress.kubernetes.io/backend-protocol": "https",
			},
		},
		Spec: v1.IngressSpec{
			Rules: []v1.IngressRule{
				{
					Host: opts.Host,
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     fmt.Sprintf("/%s(/|$)(.*)", opts.Path),
									PathType: &pathType,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: opts.ServiceName,
											Port: v1.ServiceBackendPort{
												Number: opts.ServicePort,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
