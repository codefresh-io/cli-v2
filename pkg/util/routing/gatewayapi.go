package util

import (
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
)

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
			Name: opts.Name,
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
