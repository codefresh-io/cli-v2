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

package routing

import (
	"context"
	"fmt"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util/kube"

	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/manifoldco/promptui"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
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

	ingressControllerType string

	CreateIngressOptions struct {
		Name             string
		Namespace        string
		IngressClassName string
		Annotations      map[string]string
		Host             string
		Paths            []IngressPath
	}
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

var (
	CYAN        = "\033[36m"
	COLOR_RESET = "\033[0m"

	SupportedIngressControllers = []ingressControllerType{IngressControllerNginxCommunity, IngressControllerNginxEnterprise, IngressControllerIstio, IngressControllerTraefik, IngressControllerAmbassador, IngressControllerALB, IngressControllerNginxCodefresh}
)

func (c baseController) Name() string {
	return c.name
}

func (c baseController) Decorate(route interface{}) {}

func GetIngressController(name string) RoutingController {
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

func (ingressControllerALB) Decorate(route interface{}) {
	ingress, ok := route.(*netv1.Ingress)
	if !ok {
		log.G().Error("Cant decorate, this is not an ingress!")
		return
	}
	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations["alb.ingress.kubernetes.io/group.name"] = "csdp-ingress"
	ingress.Annotations["alb.ingress.kubernetes.io/scheme"] = "internet-facing"
	ingress.Annotations["alb.ingress.kubernetes.io/target-type"] = "ip"
	ingress.Annotations["alb.ingress.kubernetes.io/listen-ports"] = "[{\"HTTP\": 80}, {\"HTTPS\": 443}]"
}

func (ingressControllerNginxEnterprise) Decorate(route interface{}) {
	ingress, ok := route.(*netv1.Ingress)
	if !ok {
		log.G().Error("Cant decorate, this is not an ingress!")
		return
	}
	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations["nginx.org/mergeable-ingress-type"] = "minion"
}

func createHTTPIngressPaths(paths []IngressPath) []netv1.HTTPIngressPath {
	var httpIngressPaths []netv1.HTTPIngressPath
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

func CreateIngress(opts *CreateRouteOpts) *netv1.Ingress {
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
					Host: opts.Hostname,
				},
			},
		},
	}

	if len(opts.Paths) > 0 {
		ingress.Spec.Rules[0].IngressRuleValue = netv1.IngressRuleValue{
			HTTP: &netv1.HTTPIngressRuleValue{
				Paths: createHTTPIngressPaths(routePathsToIngressPaths(opts.Paths)),
			},
		}
	}

	if opts.IngressClass != "" {
		ingress.Spec.IngressClassName = &opts.IngressClass
	}

	if opts.Annotations != nil {
		ingress.ObjectMeta.Annotations = opts.Annotations
	}

	return ingress
}

func ValidateIngressController(ctx context.Context, kubeFactory apkube.Factory, requestedIngressClass string) (RoutingController, string, error) {
	var (
		ingressController RoutingController
		ingressClass      string
		ingressClassNames []string
	)

	log.G(ctx).Info("Retrieving ingress class info from your cluster...\n")

	cs := kube.GetClientSetOrDie(kubeFactory)
	ingressClassList, err := cs.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get ingress class list from your cluster: %w", err)
	}

	ingressClassNameToController := make(map[string]RoutingController)

	for _, ic := range ingressClassList.Items {
		for _, controller := range SupportedIngressControllers {
			if ic.Spec.Controller == string(controller) {
				ingressClassNames = append(ingressClassNames, ic.Name)
				ingressClassNameToController[ic.Name] = GetIngressController(string(controller))

				if requestedIngressClass == ic.Name {
					// if ingress class provided via flag
					ingressClass = requestedIngressClass
				}
				break
			}
		}
	}

	if requestedIngressClass != "" {
		if ingressClass == "" {
			// if ingress class provided via flag was not found in cluster
			return nil, "", fmt.Errorf("ingress class '%s' is not supported", requestedIngressClass)
		}
	} else if len(ingressClassNames) == 0 {
		// if no ingress classes in cluster at all
		return nil, "", fmt.Errorf("no ingress classes of the supported types were found")
	} else if len(ingressClassNames) == 1 {
		// if there is only 1 ingress class in the cluster - just use it
		log.G(ctx).Info("Using ingress class: ", ingressClassNames[0])
		ingressClass = ingressClassNames[0]
	} else if len(ingressClassNames) > 1 {
		// if there are multiple ingress classes in the cluster
		if store.Get().Silent {
			return nil, "", fmt.Errorf("there are multiple ingress controllers on your cluster, please add the --ingress-class flag and define its value")
		}

		ingressClass, err = getIngressClassFromUserSelect(ingressClassNames)
		if err != nil {
			return nil, "", err
		}
	}

	ingressController = ingressClassNameToController[ingressClass]

	if ingressController.Name() == string(IngressControllerNginxEnterprise) {
		log.G(ctx).Warn("You are using the NGINX enterprise edition (nginx.org/ingress-controller) as your ingress controller. To successfully install the runtime, configure all required settings, as described in : ", store.Get().RequirementsLink)
	}

	return ingressController, ingressClass, nil
}

func getIngressClassFromUserSelect(ingressClassNames []string) (string, error) {
	templates := &promptui.SelectTemplates{
		Selected: "{{ . | yellow }} ",
	}

	labelStr := fmt.Sprintf("%vSelect ingressClass%v", CYAN, COLOR_RESET)

	prompt := promptui.Select{
		Label:     labelStr,
		Items:     ingressClassNames,
		Templates: templates,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return result, nil
}

func routePathsToIngressPaths(routePaths []RoutePath) []IngressPath {
	var ingressPaths []IngressPath
	for _, path := range routePaths {
		var ingressPathType netv1.PathType
		switch pathType := path.pathType; pathType {
		case ExactPath:
			ingressPathType = netv1.PathTypeExact
		case PrefixPath:
			ingressPathType = netv1.PathTypePrefix
		case RegexPath:
			ingressPathType = netv1.PathTypeImplementationSpecific
		}

		ingressPaths = append(ingressPaths, IngressPath{
			ServiceName: path.serviceName,
			ServicePort: int32(path.servicePort),
			Path:        path.path,
			PathType:    ingressPathType,
		})
	}

	return ingressPaths
}
