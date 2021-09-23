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
