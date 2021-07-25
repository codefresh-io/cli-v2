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

package util

import (
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/store"

	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	cdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	CreateAppOptions struct {
		Name        string
		Namespace   string
		Project     string
		SyncWave    int
		RepoURL     string
		Revision    string
		SrcPath     string
		DestServer  string
		NoFinalizer bool
	}
)

func CreateApp(opts *CreateAppOptions) *cdv1alpha1.Application {
	if opts.DestServer == "" {
		opts.DestServer = apstore.Default.DestServer
	}

	app := &cdv1alpha1.Application{
		TypeMeta: metav1.TypeMeta{
			APIVersion: cdv1alpha1.ApplicationSchemaGroupVersionKind.GroupVersion().String(),
			Kind:       cdv1alpha1.ApplicationSchemaGroupVersionKind.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
			Annotations: map[string]string{
				"argocd.argoproj.io/sync-wave": fmt.Sprintf("%d", opts.SyncWave),
			},
			Labels: map[string]string{
				apstore.Default.LabelKeyAppManagedBy: store.Get().BinaryName,
				"app.kubernetes.io/name":             opts.Name,
			},
			Finalizers: []string{
				"resources-finalizer.argocd.argoproj.io",
			},
		},
		Spec: cdv1alpha1.ApplicationSpec{
			Project: opts.Project,
			Source: cdv1alpha1.ApplicationSource{
				RepoURL:        opts.RepoURL,
				Path:           opts.SrcPath,
				TargetRevision: opts.Revision,
			},
			Destination: cdv1alpha1.ApplicationDestination{
				Server:    opts.DestServer,
				Namespace: opts.Namespace,
			},
			SyncPolicy: &cdv1alpha1.SyncPolicy{
				Automated: &cdv1alpha1.SyncPolicyAutomated{
					SelfHeal:   true,
					Prune:      true,
					AllowEmpty: true,
				},
			},
			IgnoreDifferences: []cdv1alpha1.ResourceIgnoreDifferences{
				{
					Group: cdv1alpha1.ApplicationSchemaGroupVersionKind.Group,
					Kind:  cdv1alpha1.ApplicationSchemaGroupVersionKind.Kind,
					JSONPointers: []string{
						"/status",
					},
				},
			},
		},
	}
	if opts.NoFinalizer {
		app.ObjectMeta.Finalizers = []string{}
	}

	return app
}
