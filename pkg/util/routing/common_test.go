package routing_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"testing"

	"github.com/codefresh-io/cli-v2/pkg/util/routing"
	v1 "k8s.io/api/networking/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
)

// TestCreateInternalRouterRoute calls routing.CreateInternalRouterRoute, checking
// that a correct route is returned.
// func TestCreateInternalRouterRoute(t *testing.T) {
// 	var want v1.Ingress
// 	ingressFile, err := ioutil.ReadFile("testdata/ingress.yaml")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(ingressFile), 100).Decode(&want)

// 	routeOpts := &routing.CreateRouteOpts{
// 		RuntimeName:       "test-runtime",
// 		Namespace:         "test-runtime",
// 		IngressClass:      "alb",
// 		Hostname:          "testing.foo.bar.com",
// 		IngressController: routing.GetIngressController(string(routing.IngressControllerALB)),
// 		Annotations:       nil,
// 		GatewayName:       "",
// 		GatewayNamespace:  "",
// 	}
// 	_, route := routing.CreateInternalRouterRoute(routeOpts, false, true, false)
// 	ingress, ok := route.(*v1.Ingress)
// 	if !ok {
// 		log.Fatal("Not an ingress")
// 	}

// 	if want.String() != ingress.String() {
// 		t.Fatalf("Received: %v\n, want: %v\n", ingress.String(), want.String())
// 	}
// }

// TestCreateInternalRouterRoute calls routing.CreateInternalRouterRoute, checking
// that a correct route is returned.
func TestCreateInternalRouterRoute(t *testing.T) {
	tests := map[string]struct {
		routeOpts    *routing.CreateRouteOpts
		wantFilePath string
		assertFn     func(t *testing.T, want interface{}, received interface{})
	}{
		string(routing.IngressControllerALB): {
			routeOpts: &routing.CreateRouteOpts{
				RuntimeName:       "test-runtime",
				Namespace:         "test-runtime",
				IngressClass:      "alb",
				Hostname:          "testing.foo.bar.com",
				IngressController: routing.GetIngressController(string(routing.IngressControllerALB)),
				Annotations:       nil,
				GatewayName:       "",
				GatewayNamespace:  "",
			},
			wantFilePath: "testdata/alb-ingress.yaml",
			assertFn: func(t *testing.T, wantRoute, receivedRoute interface{}) {
				received := receivedRoute.(*v1.Ingress)
				want := wantRoute.(*v1.Ingress)

				if want.String() != received.String() {
					t.Fatalf("Received: %v\n, want: %v\n", received.String(), want.String())
				}
			},
		},
		string(routing.IngressControllerNginxCommunity): {
			routeOpts: &routing.CreateRouteOpts{
				RuntimeName:       "test-runtime",
				Namespace:         "test-runtime",
				IngressClass:      "nginx",
				Hostname:          "testing.foo.bar.com",
				IngressController: routing.GetIngressController(string(routing.IngressControllerNginxCommunity)),
				Annotations:       nil,
				GatewayName:       "",
				GatewayNamespace:  "",
			},
			wantFilePath: "testdata/nginx-ingress.yaml",
			assertFn: func(t *testing.T, wantRoute, receivedRoute interface{}) {
				received := receivedRoute.(*v1.Ingress)
				want := wantRoute.(*v1.Ingress)

				if want.String() != received.String() {
					t.Fatalf("Received: %v\n, want: %v\n", received.String(), want.String())
				}
			},
		},
	}

	for tname, tt := range tests {
		t.Run(tname, func(t *testing.T) {
			var want *v1.Ingress
			ingressFile, err := ioutil.ReadFile(tt.wantFilePath)
			if err != nil {
				log.Fatal(err)
			}

			yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(ingressFile), 100).Decode(&want)
			_, received := routing.CreateInternalRouterRoute(tt.routeOpts, false, true, false)

			tt.assertFn(t, want, received)
		})
	}
}
