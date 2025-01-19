// Copyright 2025 The Codefresh Authors.
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

func CreateInternalRouterInternalRoute(opts *CreateRouteOpts, useGatewayAPI bool) (string, interface{}) {
	var route interface{}
	var routeName string

	createRouteOpts := CreateRouteOpts{
		Name:             opts.RuntimeName + store.Get().InternalRouterInternalIngressName,
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
				serviceName: store.Get().InternalRouterServiceName,
				servicePort: store.Get().InternalRouterServicePort,
			},
		},
		Annotations:       opts.Annotations,
		IngressController: opts.IngressController,
	}

	if useGatewayAPI {
		// routeName = "http-route"
		// This is a workaround until the Gateway API will support the websocket protocol
		route = createHTTPProxy(&createRouteOpts)
		routeName = "http-proxy"
	} else {
		route = CreateIngress(&createRouteOpts)
		routeName = "ingress"
	}

	opts.IngressController.Decorate(route)

	return routeName, route
}

func CreateInternalRouterRoute(opts *CreateRouteOpts, useGatewayAPI bool, includeInternalRoutes bool, onlyWebhooks bool) (string, interface{}) {
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
				path:        store.Get().WebhooksIngressPath,
				serviceName: store.Get().InternalRouterServiceName,
				servicePort: store.Get().InternalRouterServicePort,
			},
		},
		Annotations:       opts.Annotations,
		IngressController: opts.IngressController,
	}

	// on upgrade, we do not want collisions with existing ingresses
	if !onlyWebhooks {
		createRouteOpts.Paths = append(createRouteOpts.Paths,
			RoutePath{
				pathType:    PrefixPath,
				path:        store.Get().ArgoWfIngressPath,
				serviceName: store.Get().InternalRouterServiceName,
				servicePort: store.Get().InternalRouterServicePort,
			},
		)
	}

	// when using internal ingress -- we need to extract app-proxy
	// to a separate ingress (with its own host and annotations)
	if !onlyWebhooks && includeInternalRoutes {
		createRouteOpts.Paths = append(createRouteOpts.Paths,
			RoutePath{
				pathType:    PrefixPath,
				path:        store.Get().AppProxyIngressPath,
				serviceName: store.Get().InternalRouterServiceName,
				servicePort: store.Get().InternalRouterServicePort,
			},
		)
	}

	if useGatewayAPI {
		route = createHTTPProxy(&createRouteOpts)
		routeName = "http-proxy"
	} else {
		route = CreateIngress(&createRouteOpts)
		routeName = "ingress"
	}

	opts.IngressController.Decorate(route)

	return routeName, route
}
