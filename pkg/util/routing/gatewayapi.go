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

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/cli-v2/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1beta1"
	client "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

type (
	HTTPRouteRule struct {
		Path        string
		PathType    gatewayapi.PathMatchType
		ServiceName string
		ServicePort int32
	}

	gatewayControllerType string
)

func GetGatewayController(name string) RoutingController {
	b := baseController{name}
	switch name {
	default:
		return b
	}
}

const GatewayControllerContour gatewayControllerType = "projectcontour.io/projectcontour/contour"

var SupportedGatewayControllers = []gatewayControllerType{GatewayControllerContour}

func createHTTPRoute(opts *CreateRouteOpts) *gatewayapi.HTTPRoute {
	name := gatewayapi.ObjectName(opts.GatewayName)
	namespace := gatewayapi.Namespace(opts.GatewayNamespace)

	httpRoute := &gatewayapi.HTTPRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: gatewayapi.SchemeGroupVersion.String(),
			Kind:       "HTTPRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
		},
		Spec: gatewayapi.HTTPRouteSpec{
			CommonRouteSpec: gatewayapi.CommonRouteSpec{
				ParentRefs: []gatewayapi.ParentReference{
					{
						Name:      name,
						Namespace: &namespace,
					},
				},
			},
			Rules: createHTTPRouteRules(routePathsToHTTPRouteRule(opts.Paths)),
		},
	}

	if opts.Annotations != nil {
		httpRoute.ObjectMeta.Annotations = opts.Annotations
	}

	return httpRoute
}

func createHTTPRouteRules(rules []HTTPRouteRule) []gatewayapi.HTTPRouteRule {
	var httpRouteRules []gatewayapi.HTTPRouteRule
	for _, p := range rules {
		httpRouteRules = append(httpRouteRules, gatewayapi.HTTPRouteRule{
			Matches: []gatewayapi.HTTPRouteMatch{
				{
					Path: &gatewayapi.HTTPPathMatch{
						Type:  &p.PathType,
						Value: &p.Path,
					},
				},
			},
			BackendRefs: []gatewayapi.HTTPBackendRef{
				{
					BackendRef: gatewayapi.BackendRef{
						BackendObjectReference: gatewayapi.BackendObjectReference{
							Name: gatewayapi.ObjectName(p.ServiceName),
							Port: (*gatewayapi.PortNumber)(&p.ServicePort),
						},
					},
				},
			},
		})
	}

	return httpRouteRules
}

func ValidateGatewayController(ctx context.Context, kubeFactory kube.Factory, gatewayName, gatewayNamespace string) (RoutingController, error) {
	// Get Gateway
	cs := getClientsetOrDie(kubeFactory)
	gateway, err := cs.GatewayV1beta1().Gateways(gatewayNamespace).Get(ctx, gatewayName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get gateway resource from your cluster: %w", err)
	}

	// Get GatewayClass
	gatewayClassName := string(gateway.Spec.GatewayClassName)
	gatewayClass, err := cs.GatewayV1beta1().GatewayClasses().Get(ctx, gatewayClassName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get gatewayclass resource from your cluster: %w", err)
	}

	// Check if GatewayController is supported
	gatewayController := gatewayClass.Spec.ControllerName
	for _, controller := range SupportedGatewayControllers {
		if controller == gatewayControllerType(gatewayController) {
			log.G().Infof("GatewayController detected: \"%s\" !\n", gatewayController)
			return GetGatewayController(string(controller)), nil
		}
	}

	return nil, fmt.Errorf("Gateway controller %s is not supported", gatewayController)
}

func routePathsToHTTPRouteRule(routePaths []RoutePath) []HTTPRouteRule {
	var httpRouteRules []HTTPRouteRule
	for _, path := range routePaths {
		var ingressPathType gatewayapi.PathMatchType
		switch pathType := path.pathType; pathType {
		case ExactPath:
			ingressPathType = gatewayapi.PathMatchExact
		case PrefixPath:
			ingressPathType = gatewayapi.PathMatchPathPrefix
		case RegexPath:
			ingressPathType = gatewayapi.PathMatchRegularExpression
		}

		httpRouteRules = append(httpRouteRules, HTTPRouteRule{
			ServiceName: path.serviceName,
			ServicePort: int32(path.servicePort),
			Path:        path.path,
			PathType:    ingressPathType,
		})
	}

	return httpRouteRules
}

func getClientsetOrDie(kubeFactory kube.Factory) *client.Clientset {
	restConfig, err := kubeFactory.ToRESTConfig()
	if err != nil {
		panic(err)
	}

	return client.NewForConfigOrDie(restConfig)
}
