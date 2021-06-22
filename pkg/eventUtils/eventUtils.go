// Copyright 2021 The Codefresh Authors.
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

package eventUtils

import (
	"github.com/codefresh-io/cli-v2/pkg/store"

	apicommon "github.com/argoproj/argo-events/pkg/apis/common"
	eventsourcereg "github.com/argoproj/argo-events/pkg/apis/eventsource"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorreg "github.com/argoproj/argo-events/pkg/apis/sensor"
	sensorsv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type (
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
