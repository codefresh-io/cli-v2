package util

import (
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/store"

	"github.com/codefresh-io/cli-v2/pkg/util"
	netv1 "k8s.io/api/networking/v1"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type CreateRouteOpts struct {
	RuntimeName         string
	Namespace           string
	IngressClass        string
	Hostname            string
	InternalAnnotations map[string]string
	ExternalAnnotations map[string]string
	IngressController   IngressController
	GatewayName         string
	GatewayNamespace    string
}

func CreateAppProxyRoute(opts *CreateRouteOpts, useGatewayAPI bool) interface{} {
	if useGatewayAPI {
		httpRouteOpts := CreateHTTPRouteOptions{
			Name:             opts.RuntimeName + store.Get().AppProxyIngressName,
			Namespace:        opts.Namespace,
			GatewayName:      opts.GatewayName,
			GatewayNamespace: opts.GatewayNamespace,
			Host:             opts.Hostname,
			Rules: []HTTPRouteRule{
				{
					Path:        store.Get().AppProxyIngressPath,
					PathType:    gatewayapi.PathMatchPathPrefix,
					ServiceName: store.Get().AppProxyServiceName,
					ServicePort: store.Get().AppProxyServicePort,
				},
			},
		}

		if opts.InternalAnnotations != nil {
			httpRouteOpts.Annotations = make(map[string]string)
			mergeAnnotations(httpRouteOpts.Annotations, opts.InternalAnnotations)
		}

		httpRoute := createHTTPRoute(&httpRouteOpts)

		return httpRoute
	} else {
		ingressOpts := CreateIngressOptions{
			Name:             opts.RuntimeName + store.Get().AppProxyIngressName,
			Namespace:        opts.Namespace,
			IngressClassName: opts.IngressClass,
			Host:             opts.Hostname,
			Paths: []IngressPath{
				{
					Path:        store.Get().AppProxyIngressPath,
					PathType:    netv1.PathTypePrefix,
					ServiceName: store.Get().AppProxyServiceName,
					ServicePort: store.Get().AppProxyServicePort,
				},
			},
		}

		if opts.InternalAnnotations != nil {
			ingressOpts.Annotations = make(map[string]string)
			mergeAnnotations(ingressOpts.Annotations, opts.InternalAnnotations)
		}

		ingress := CreateIngress(&ingressOpts)
		opts.IngressController.Decorate(ingress)

		return ingress
	}
}

func CreateDemoPipelinesRoute(opts *CreateRouteOpts, useGatewayAPI bool) interface{} {
	if useGatewayAPI {
		httpRouteOpts := CreateHTTPRouteOptions{
			Name:             store.Get().DemoPipelinesIngressObjectName,
			GatewayName:      opts.GatewayName,
			GatewayNamespace: opts.GatewayNamespace,
			Host:             opts.Hostname,
			Rules: []HTTPRouteRule{
				{
					Path:        util.GenerateIngressPathForDemoGitEventSource(opts.RuntimeName),
					ServiceName: store.Get().DemoGitEventSourceObjectName + "-eventsource-svc",
					ServicePort: store.Get().DemoGitEventSourceServicePort,
					PathType:    gatewayapi.PathMatchPathPrefix,
				},
			},
		}

		return createHTTPRoute(&httpRouteOpts)
	} else {
		ingressOpts := CreateIngressOptions{
			Name:             opts.RuntimeName + store.Get().AppProxyIngressName,
			IngressClassName: opts.IngressClass,
			Host:             opts.Hostname,
			Paths: []IngressPath{
				{
					Path:        util.GenerateIngressPathForDemoGitEventSource(opts.RuntimeName),
					ServiceName: store.Get().DemoGitEventSourceObjectName + "-eventsource-svc",
					ServicePort: store.Get().DemoGitEventSourceServicePort,
					PathType:    netv1.PathTypePrefix,
				},
			},
		}

		ingress := CreateIngress(&ingressOpts)
		opts.IngressController.Decorate(ingress)

		return ingress
	}
}

func CreateWorkflowsRoute(opts *CreateRouteOpts, useGatewayAPI bool) interface{} {
	if useGatewayAPI {
		httpRouteOpts := CreateHTTPRouteOptions{
			Name:             store.Get().DemoPipelinesIngressObjectName,
			GatewayName:      opts.GatewayName,
			GatewayNamespace: opts.GatewayNamespace,
			Host:             opts.Hostname,
			Rules: []HTTPRouteRule{
				{
					Path:        util.GenerateIngressPathForDemoGitEventSource(opts.RuntimeName),
					ServiceName: store.Get().DemoGitEventSourceObjectName + "-eventsource-svc",
					ServicePort: store.Get().DemoGitEventSourceServicePort,
					PathType:    gatewayapi.PathMatchPathPrefix,
				},
			},
		}

		if opts.ExternalAnnotations != nil {
			mergeAnnotations(httpRouteOpts.Annotations, opts.ExternalAnnotations)
		}

		return createHTTPRoute(&httpRouteOpts)
	} else {
		ingressOpts := CreateIngressOptions{
			Name:             opts.RuntimeName + store.Get().WorkflowsIngressName,
			Namespace:        opts.Namespace,
			IngressClassName: opts.IngressClass,
			Host:             opts.Hostname,
			Annotations: map[string]string{
				"ingress.kubernetes.io/protocol":               "https",
				"ingress.kubernetes.io/rewrite-target":         "/$2",
				"nginx.ingress.kubernetes.io/backend-protocol": "https",
				"nginx.ingress.kubernetes.io/rewrite-target":   "/$2",
			},
			Paths: []IngressPath{
				{
					Path:        fmt.Sprintf("/%s(/|$)(.*)", store.Get().WorkflowsIngressPath),
					PathType:    netv1.PathTypeImplementationSpecific,
					ServiceName: store.Get().ArgoWFServiceName,
					ServicePort: store.Get().ArgoWFServicePort,
				},
			},
		}

		if opts.ExternalAnnotations != nil {
			mergeAnnotations(ingressOpts.Annotations, opts.ExternalAnnotations)
		}

		ingress := CreateIngress(&ingressOpts)
		opts.IngressController.Decorate(ingress)

		return ingress
	}
}

func mergeAnnotations(annotation map[string]string, newAnnotation map[string]string) {
	for key, element := range newAnnotation {
		annotation[key] = element
	}
}
