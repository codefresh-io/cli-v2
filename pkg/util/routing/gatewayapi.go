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
	"context"
	"fmt"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/cli-v2/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type (
	CreateHTTPRouteOptions struct {
		Name             string
		Namespace        string
		GatewayName      string
		GatewayNamespace string
		Annotations      map[string]string
		Host             string
		Rules            []HTTPRouteRule
	}

	HTTPRouteRule struct {
		Path        string
		PathType    gatewayapi.PathMatchType
		ServiceName string
		ServicePort int32
	}

	gatewayControllerType string
)

func GetGatewayController(name string) Controller {
	b := baseController{name}
	switch name {
	default:
		return b
	}
}

const GatewayControllerContour gatewayControllerType = "projectcontour.io/projectcontour/contour"

var SupportedGatewayControllers = []gatewayControllerType{GatewayControllerContour}

func createHTTPRoute(opts *CreateHTTPRouteOptions) *gatewayapi.HTTPRoute {
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
			Rules: createHTTPRouteRules(opts.Rules),
		},
	}

	if opts.Annotations != nil {
		httpRoute.ObjectMeta.Annotations = opts.Annotations
	}

	return httpRoute
}

func createHTTPRouteRules(rules []HTTPRouteRule) []gatewayapi.HTTPRouteRule {
	httpRouteRules := make([]gatewayapi.HTTPRouteRule, 0, len(rules))
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

func ValidateGatewayController(ctx context.Context, kubeFactory kube.Factory, gatewayName, gatewayNamespace string) (Controller, error) {
	// Get Gateway
	gatewayResourceId := gatewayapi.SchemeGroupVersion.WithResource("gateways")

	cs := kubeFactory.KubernetesDynamicClientSetOrDie()
	gateway, err := cs.Resource(gatewayResourceId).Namespace("test-runtime").Get(ctx, gatewayName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get gateway resource from your cluster: %w", err)
	}

	// Get GatewayClass
	gatewayClassName := gateway.Object["spec"].(map[string]interface{})["gatewayClassName"].(string)
	gatewayClassResourceId := gatewayapi.SchemeGroupVersion.WithResource("gatewayclasses")
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
