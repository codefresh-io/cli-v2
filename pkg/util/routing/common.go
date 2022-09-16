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
	"github.com/codefresh-io/cli-v2/pkg/store"

	"github.com/codefresh-io/cli-v2/pkg/util"
)

type (
	RoutingController interface {
		Name() string
		Decorate(route interface{})
	}

	RoutePath struct {
		serviceName string
		servicePort int32
		pathType    RoutePathType
		path        string
	}

	CreateRouteOpts struct {
		Name              string
		RuntimeName       string
		Namespace         string
		IngressClass      string
		Hostname          string
		Paths             []RoutePath
		Annotations       map[string]string
		IngressController RoutingController
		GatewayName       string
		GatewayNamespace  string
	}

	RoutePathType string
)

const ExactPath RoutePathType = "Exact"
const PrefixPath RoutePathType = "Prefix"
const RegexPath RoutePathType = "Regex"

func CreateAppProxyRoute(opts *CreateRouteOpts, useGatewayAPI bool) (string, interface{}) {
	var route interface{}
	var routeName string

	createRouteOpts := CreateRouteOpts{
		Name:             opts.RuntimeName + store.Get().AppProxyIngressName,
		Namespace:        opts.Namespace,
		GatewayName:      opts.GatewayName,
		GatewayNamespace: opts.GatewayNamespace,
		Hostname:         opts.Hostname,
		RuntimeName:      opts.RuntimeName,
		IngressClass:     opts.IngressClass,
		Paths: []RoutePath{
			{
				pathType:    PrefixPath,
				path:        store.Get().AppProxyIngressPath,
				serviceName: store.Get().AppProxyServiceName,
				servicePort: store.Get().AppProxyServicePort,
			},
		},
		Annotations:       opts.Annotations,
		IngressController: opts.IngressController,
	}

	if useGatewayAPI {
		// routeName = "http-route"
		// This is a workaround until the Gateway API will suport the websocket protocol
		route = createHTTPProxy(&createRouteOpts)
		routeName = "http-proxy"
	} else {
		route = CreateIngress(&createRouteOpts)
		routeName = "ingress"
	}

	opts.IngressController.Decorate(route)

	return routeName, route
}

func CreateDemoPipelinesRoute(opts *CreateRouteOpts, useGatewayAPI bool) (string, interface{}) {
	var route interface{}
	var routeName string

	createRouteOpts := CreateRouteOpts{
		Name:             store.Get().DemoPipelinesIngressObjectName,
		Namespace:        opts.Namespace,
		GatewayName:      opts.GatewayName,
		GatewayNamespace: opts.GatewayNamespace,
		Hostname:         opts.Hostname,
		RuntimeName:      opts.RuntimeName,
		IngressClass:     opts.IngressClass,
		Paths: []RoutePath{
			{
				pathType:    PrefixPath,
				path:        util.GenerateIngressPathForDemoGitEventSource(opts.RuntimeName),
				serviceName: store.Get().DemoGitEventSourceObjectName + "-eventsource-svc",
				servicePort: store.Get().DemoGitEventSourceServicePort,
			},
		},
		Annotations:       opts.Annotations,
		IngressController: opts.IngressController,
	}

	if useGatewayAPI {
		route = createHTTPRoute(&createRouteOpts)
		routeName = "http-route"
	} else {
		route = CreateIngress(&createRouteOpts)
		routeName = "ingress"
	}

	opts.IngressController.Decorate(route)

	return routeName, route
}

func CreateInternalRouterRoute(opts *CreateRouteOpts, useGatewayAPI bool) (string, interface{}) {
	var route interface{}
	var routeName string

	createRouteOpts := CreateRouteOpts{
		Name:             opts.RuntimeName + store.Get().InternalRouterIngressName,
		Namespace:        opts.Namespace,
		GatewayName:      opts.GatewayName,
		GatewayNamespace: opts.GatewayNamespace,
		Hostname:         opts.Hostname,
		RuntimeName:      opts.RuntimeName,
		IngressClass:     opts.IngressClass,
		Paths: []RoutePath{
			{
				pathType:    PrefixPath,
				path:        store.Get().InternalRouterIngressPath,
				serviceName: store.Get().InternalRouterServiceName,
			},
		},
		Annotations:       opts.Annotations,
		IngressController: opts.IngressController,
	}

	if useGatewayAPI {
		route = createHTTPRoute(&createRouteOpts)
		routeName = "http-route"
	} else {
		if createRouteOpts.Annotations == nil {
			createRouteOpts.Annotations = make(map[string]string)
		}
		mergeAnnotations(createRouteOpts.Annotations, map[string]string{
			"ingress.kubernetes.io/protocol":               "https",
			"ingress.kubernetes.io/rewrite-target":         "/$2",
			"nginx.ingress.kubernetes.io/backend-protocol": "https",
			"nginx.ingress.kubernetes.io/rewrite-target":   "/$2",
		})
		route = CreateIngress(&createRouteOpts)
		routeName = "ingress"
	}

	opts.IngressController.Decorate(route)

	return routeName, route
}

func mergeAnnotations(annotation map[string]string, newAnnotation map[string]string) {
	for key, element := range newAnnotation {
		annotation[key] = element
	}
}
