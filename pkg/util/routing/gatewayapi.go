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
	httproute "github.com/codefresh-io/cli-v2/pkg/util/routing/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type (
	HTTPRouteRule struct {
		Path        string
		PathType    httproute.PathMatchType
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

func createHTTPRoute(opts *CreateRouteOpts) *httproute.HTTPRoute {
	name := httproute.ObjectName(opts.GatewayName)
	namespace := httproute.Namespace(opts.GatewayNamespace)

	httpRoute := &httproute.HTTPRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "gateway.networking.k8s.io/v1beta1",
			Kind:       "HTTPRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
		},
		Spec: httproute.HTTPRouteSpec{
			CommonRouteSpec: httproute.CommonRouteSpec{
				ParentRefs: []httproute.ParentReference{
					{
						Name:      name,
						Namespace: &namespace,
					},
				},
			},
			Hostnames: []httproute.Hostname{httproute.Hostname(opts.Hostname)},
			Rules:     createHTTPRouteRules(routePathsToHTTPRouteRules(opts.Paths)),
		},
	}

	if opts.Annotations != nil {
		httpRoute.ObjectMeta.Annotations = opts.Annotations
	}

	return httpRoute
}

func createHTTPRouteRules(rules []HTTPRouteRule) []httproute.HTTPRouteRule {
	var httpRouteRules []httproute.HTTPRouteRule
	for _, p := range rules {
		httpRouteRules = append(httpRouteRules, httproute.HTTPRouteRule{
			Matches: []httproute.HTTPRouteMatch{
				{
					Path: &httproute.HTTPPathMatch{
						Type:  &p.PathType,
						Value: &p.Path,
					},
				},
			},
			BackendRefs: []httproute.HTTPBackendRef{
				{
					BackendRef: httproute.BackendRef{
						BackendObjectReference: httproute.BackendObjectReference{
							Name: httproute.ObjectName(p.ServiceName),
							Port: (*httproute.PortNumber)(&p.ServicePort),
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
	gatewayResourceId := schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Version:  "v1beta1",
		Resource: "gateways",
	}
	gateway, err := cs.Resource(gatewayResourceId).Namespace(gatewayNamespace).Get(ctx, gatewayName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get gateway resource from your cluster: %w", err)
	}

	// Get GatewayClass
	gatewayClassName := gateway.Object["spec"].(map[string]interface{})["gatewayClassName"].(string)
	gatewayClassResourceId := schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Version:  "v1beta1",
		Resource: "gatewayclasses",
	}
	gatewayClass, err := cs.Resource(gatewayClassResourceId).Get(ctx, gatewayClassName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get gatewayclass resource from your cluster: %w", err)
	}

	// Check if GatewayController is supported
	gatewayController := gatewayClass.Object["spec"].(map[string]interface{})["controllerName"].(string)
	for _, controller := range SupportedGatewayControllers {
		if controller == gatewayControllerType(gatewayController) {
			log.G().Infof("GatewayController detected: \"%s\" !\n", gatewayController)
			return GetGatewayController(string(controller)), nil
		}
	}

	return nil, fmt.Errorf("Gateway controller %s is not supported", gatewayController)
}

func routePathsToHTTPRouteRules(routePaths []RoutePath) []HTTPRouteRule {
	var httpRouteRules []HTTPRouteRule
	for _, path := range routePaths {
		var ingressPathType httproute.PathMatchType
		switch pathType := path.pathType; pathType {
		case ExactPath:
			ingressPathType = httproute.PathMatchExact
		case PrefixPath:
			ingressPathType = httproute.PathMatchPathPrefix
		case RegexPath:
			ingressPathType = httproute.PathMatchRegularExpression
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

func getClientsetOrDie(kubeFactory kube.Factory) dynamic.Interface {
	restConfig, err := kubeFactory.ToRESTConfig()
	if err != nil {
		panic(err)
	}

	return dynamic.NewForConfigOrDie(restConfig)
}
