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

package util

import (
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	IngressController interface {
		Name() string
		Decorate(ingress *netv1.Ingress)
	}

	baseController struct {
		name string
	}

	ingressControllerALB struct {
		baseController
	}

	ingressControllerNginxEnterprise struct {
		baseController
	}

	IngressPath struct {
		Path        string
		PathType    netv1.PathType
		ServiceName string
		ServicePort int32
	}

	CreateIngressOptions struct {
		Name             string
		Namespace        string
		IngressClassName string
		Annotations      map[string]string
		Host             string
		Paths            []IngressPath
	}

	ingressControllerType string
)

const (
	IngressControllerNginxCommunity  ingressControllerType = "k8s.io/ingress-nginx"
	IngressControllerNginxEnterprise ingressControllerType = "nginx.org/ingress-controller"
	IngressControllerIstio           ingressControllerType = "istio.io/ingress-controller"
	IngressControllerTraefik         ingressControllerType = "traefik.io/ingress-controller"
	IngressControllerAmbassador      ingressControllerType = "getambassador.io/ingress-controller"
	IngressControllerALB             ingressControllerType = "ingress.k8s.aws/alb"
	IngressControllerNginxCodefresh  ingressControllerType = "k8s.io/ingress-nginx-codefresh"
)

var SupportedControllers = []ingressControllerType{IngressControllerNginxCommunity, IngressControllerNginxEnterprise, IngressControllerIstio, IngressControllerTraefik, IngressControllerAmbassador, IngressControllerALB, IngressControllerNginxCodefresh}

func (c baseController) Name() string {
	return c.name
}

func (c baseController) Decorate(ingress *netv1.Ingress) {}

func GetController(name string) IngressController {
	b := baseController{name}
	switch name {
	case string(IngressControllerALB):
		return ingressControllerALB{b}
	case string(IngressControllerNginxEnterprise):
		return ingressControllerNginxEnterprise{b}
	default:
		return b
	}
}

func (ingressControllerALB) Decorate(ingress *netv1.Ingress) {
	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations["alb.ingress.kubernetes.io/group.name"] = "csdp-ingress"
	ingress.Annotations["alb.ingress.kubernetes.io/scheme"] = "internet-facing"
	ingress.Annotations["alb.ingress.kubernetes.io/target-type"] = "ip"
	ingress.Annotations["alb.ingress.kubernetes.io/listen-ports"] = "[{\"HTTP\": 80}, {\"HTTPS\": 443}]"
}

func (ingressControllerNginxEnterprise) Decorate(ingress *netv1.Ingress) {
	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations["nginx.org/mergeable-ingress-type"] = "minion"
}

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
	opts.Name = strings.TrimSuffix(opts.Name, "/")

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
				},
			},
		},
	}

	if len(opts.Paths) > 0 {
		ingress.Spec.Rules[0].IngressRuleValue = netv1.IngressRuleValue{
			HTTP: &netv1.HTTPIngressRuleValue{
				Paths: createHTTPIngressPaths(opts.Paths),
			},
		}
	}

	if opts.IngressClassName != "" {
		ingress.Spec.IngressClassName = &opts.IngressClassName
	}

	if opts.Annotations != nil {
		ingress.ObjectMeta.Annotations = opts.Annotations
	}

	return ingress
}
