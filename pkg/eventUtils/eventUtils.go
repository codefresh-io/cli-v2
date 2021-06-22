package eventUtils

import (
	"github.com/codefresh-io/cli-v2/pkg/store"

	apicommon "github.com/argoproj/argo-events/pkg/apis/common"
	eventbusreg "github.com/argoproj/argo-events/pkg/apis/eventbus"
	eventbusv1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventbus/v1alpha1"
	eventsourcereg "github.com/argoproj/argo-events/pkg/apis/eventsource"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorreg "github.com/argoproj/argo-events/pkg/apis/sensor"
	sensorsv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type (
	CreateEventBusOptions struct {
		Name      string
		Namespace string
	}
	CreateEventDependencyOptions struct {
		Name            string
		EventSourceName string
		EventName       string
	}

	CreateEventSourceOptions struct {
		Name               string
		Namespace          string
		ServiceAccountName string
		EventBusName       string
		Resource           map[string]CreateResourceEventSourceOptions
	}

	CreateResourceEventSourceOptions struct {
		Group     string
		Version   string
		Resource  string
		Namespace string
		Selectors []CreateSelectorOptions
	}

	CreateSelectorOptions struct {
		Key       string
		Operation string
		Value     string
	}

	CreateSensorOptions struct {
		Name            string
		Namespace       string
		EventSourceName string
		EventBusName    string
		TriggerURL      string
		Triggers        []string
	}

	CreateTriggerOptions struct {
		Conditions     string
		URL            string
		DependencyName string
	}
)

func CreateEventBus(opts *CreateEventBusOptions) *eventbusv1alpha1.EventBus {
	return &eventbusv1alpha1.EventBus{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventbusreg.Kind,
			APIVersion: eventbusreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
		},
		Spec: eventbusv1alpha1.EventBusSpec{
			NATS: &eventbusv1alpha1.NATSBus{
				Native: &eventbusv1alpha1.NativeStrategy{
					Replicas: 3,
					Auth:     &eventbusv1alpha1.AuthStrategyToken,
				},
			},
		},
	}
}

func CreateEventDependency(opts *CreateEventDependencyOptions) *sensorsv1alpha1.EventDependency {
	return &sensorsv1alpha1.EventDependency{
		Name:            opts.Name,
		EventSourceName: opts.EventSourceName,
		EventName:       opts.EventName,
	}
}

func CreateEventSource(opts *CreateEventSourceOptions) *eventsourcev1alpha1.EventSource {
	resource := make(map[string]eventsourcev1alpha1.ResourceEventSource)
	for key, res := range opts.Resource {
		resource[key] = *CreateResourceEventSource(&res)
	}

	return &eventsourcev1alpha1.EventSource{
		TypeMeta: metav1.TypeMeta{
			Kind:       eventsourcereg.Kind,
			APIVersion: eventsourcereg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
		},
		Spec: eventsourcev1alpha1.EventSourceSpec{
			Template: &eventsourcev1alpha1.Template{
				ServiceAccountName: opts.ServiceAccountName,
			},
			Service: &eventsourcev1alpha1.Service{
				Ports: []v1.ServicePort{
					{
						Port:       int32(12000),
						TargetPort: intstr.FromInt(12000),
					},
				},
			},
			EventBusName: opts.EventBusName,
			Resource:     resource,
		},
	}
}

func CreateResourceEventSource(opts *CreateResourceEventSourceOptions) *eventsourcev1alpha1.ResourceEventSource {
	selectors := make([]eventsourcev1alpha1.Selector, len(opts.Selectors))
	for i, selector := range opts.Selectors {
		selectors[i] = *CreateSelector(&selector)
	}

	return &eventsourcev1alpha1.ResourceEventSource{
		EventTypes: []eventsourcev1alpha1.ResourceEventType{
			eventsourcev1alpha1.ADD,
			eventsourcev1alpha1.UPDATE,
			eventsourcev1alpha1.DELETE,
		},
		GroupVersionResource: metav1.GroupVersionResource{
			Group:    opts.Group,   //"argoproj.io",
			Version:  opts.Version, //"v1alpha1",
			Resource: opts.Resource,
		},
		Namespace: opts.Namespace,
		Filter: &eventsourcev1alpha1.ResourceFilter{
			Labels: selectors,
		},
	}
}

func CreateSelector(opts *CreateSelectorOptions) *eventsourcev1alpha1.Selector {
	return &eventsourcev1alpha1.Selector{
		Key:       opts.Key,
		Operation: opts.Operation,
		Value:     opts.Value,
	}
}

func CreateSensor(opts *CreateSensorOptions) *sensorsv1alpha1.Sensor {
	dependencies := make([]sensorsv1alpha1.EventDependency, len(opts.Triggers))
	triggers := make([]sensorsv1alpha1.Trigger, len(opts.Triggers))
	for i, trigger := range opts.Triggers {
		dependencies[i] = *CreateEventDependency(&CreateEventDependencyOptions{
			Name:            trigger,
			EventSourceName: opts.EventSourceName,
			EventName:       trigger,
		})
		triggers[i] = *CreateTrigger(&CreateTriggerOptions{
			Conditions:     trigger,
			URL:            opts.TriggerURL,
			DependencyName: trigger,
		})
	}

	return &sensorsv1alpha1.Sensor{
		TypeMeta: metav1.TypeMeta{
			Kind:       sensorreg.Kind,
			APIVersion: sensorreg.Group + "/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
		},
		Spec: sensorsv1alpha1.SensorSpec{
			EventBusName: opts.EventBusName,
			Dependencies: dependencies,
			Triggers:     triggers,
		},
	}
}

func CreateTrigger(opts *CreateTriggerOptions) *sensorsv1alpha1.Trigger {
	return &sensorsv1alpha1.Trigger{
		Template: &sensorsv1alpha1.TriggerTemplate{
			Conditions: opts.Conditions,
			Name:       "http-trigger",
			HTTP: &sensorsv1alpha1.HTTPTrigger{
				URL:    opts.URL,
				Method: "POST",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				SecureHeaders: []*apicommon.SecureHeader{
					{
						Name: "Authorization",
						ValueFrom: &apicommon.ValueFromSource{
							SecretKeyRef: &v1.SecretKeySelector{
								LocalObjectReference: v1.LocalObjectReference{
									Name: store.Get().CFTokenSecret,
								},
								Key: store.Get().CFTokenSecretKey,
							},
						},
					},
				},
				Payload: []sensorsv1alpha1.TriggerParameter{
					{
						Src: &sensorsv1alpha1.TriggerParameterSource{
							DependencyName: opts.DependencyName,
							DataKey:        "body",
						},
						Dest: "data",
					},
				},
			},
		},
		RetryStrategy: &apicommon.Backoff{
			Steps: 3,
			Duration: &apicommon.Int64OrString{
				StrVal: "3s",
			},
		},
	}
}
