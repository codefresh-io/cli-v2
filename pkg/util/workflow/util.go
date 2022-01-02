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
	wf "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	CreateWorkflowOptions struct {
		GenerateName          string
		SpecWfTemplateRefName string
		Parameters            []string
	}
)

func CreateWorkflow(opts *CreateWorkflowOptions) *wfv1alpha1.Workflow {
	parameters := make([]wfv1alpha1.Parameter, len(opts.Parameters))
	for i, param := range opts.Parameters {
		parameters[i] = wfv1alpha1.Parameter{Name: param}
	}

	return &wfv1alpha1.Workflow{
		TypeMeta: metav1.TypeMeta{
			APIVersion: wf.APIVersion,
			Kind:       wf.WorkflowKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: opts.GenerateName,
		},
		Spec: wfv1alpha1.WorkflowSpec{
			WorkflowTemplateRef: &wfv1alpha1.WorkflowTemplateRef{
				Name: opts.SpecWfTemplateRefName,
			},
			Arguments: wfv1alpha1.Arguments{
				Parameters: parameters,
			},
		},
	}
}
