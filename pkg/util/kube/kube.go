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

package kube

import (
	"context"
	"fmt"
	"strings"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/cli-v2/pkg/store"
	authv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type (
	rbacValidation struct {
		Namespace string
		Resource  string
		Verbs     []string
		Group     string
	}

	validationRequest struct {
		cpu        string
		memorySize string
		rbac       []rbacValidation
	}
)

func EnsureClusterRequirements(ctx context.Context, kubeFactory kube.Factory, namespace string) error {
	requirementsValidationErrorMessage := "cluster does not meet minimum requirements"
	var specificErrorMessages []string

	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("cannot create kubernetes clientset: %v ", err)
	}

	req := validationRequest{
		rbac: []rbacValidation{
			{
				Resource:  "ServiceAccount",
				Verbs:     []string{"create", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "ConfigMap",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "Service",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "Role",
				Group:     "rbac.authorization.k8s.io",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "RoleBinding",
				Group:     "rbac.authorization.k8s.io",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "persistentvolumeclaims",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
			{
				Resource:  "pods",
				Verbs:     []string{"create", "update", "delete"},
				Namespace: namespace,
			},
		},
		memorySize: store.Get().MinimumMemorySizeRequired,
		cpu:        store.Get().MinimumCpuRequired,
	}

	specs := []*authv1.SelfSubjectAccessReview{}
	for _, rbac := range req.rbac {
		for _, verb := range rbac.Verbs {
			attr := &authv1.ResourceAttributes{
				Resource: rbac.Resource,
				Verb:     verb,
				Group:    rbac.Group,
			}
			if rbac.Namespace != "" {
				attr.Namespace = rbac.Namespace
			}
			specs = append(specs, &authv1.SelfSubjectAccessReview{
				Spec: authv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: attr,
				},
			})
		}
	}

	rbacres := testRBAC(ctx, client, specs)
	if len(rbacres) > 0 {
		specificErrorMessages = append(specificErrorMessages, rbacres...)
		return fmt.Errorf("%s: failed testing rbac: %v", requirementsValidationErrorMessage, specificErrorMessages)
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("%s: failed getting nodes: %v", requirementsValidationErrorMessage, err)
	}

	if len(nodes.Items) == 0 {
		return fmt.Errorf("%s: No nodes in cluster", requirementsValidationErrorMessage)
	}

	atLeastOneMet := false
	for _, n := range nodes.Items {
		res := testNode(n, req)
		if len(res) > 0 {
			specificErrorMessages = append(specificErrorMessages, res...)
		} else {
			atLeastOneMet = true
		}
	}
	if !atLeastOneMet {
		return fmt.Errorf("%s: %v", requirementsValidationErrorMessage, specificErrorMessages)
	}

	return nil
}

func testRBAC(ctx context.Context, client kubernetes.Interface, specs []*authv1.SelfSubjectAccessReview) []string {
	res := []string{}
	for _, sar := range specs {
		resp, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
		if err != nil {
			res = append(res, err.Error())
			continue
		}
		if !resp.Status.Allowed {
			verb := sar.Spec.ResourceAttributes.Verb
			namespace := sar.Spec.ResourceAttributes.Namespace
			resource := sar.Spec.ResourceAttributes.Resource
			group := sar.Spec.ResourceAttributes.Group
			msg := strings.Builder{}
			msg.WriteString(fmt.Sprintf("Insufficient permission, %s %s/%s is not allowed", verb, group, resource))
			if namespace != "" {
				msg.WriteString(fmt.Sprintf(" on namespace %s", namespace))
			}
			res = append(res, msg.String())
		}
	}
	return res
}

func testNode(n v1.Node, req validationRequest) []string {
	result := []string{}

	if req.cpu != "" {
		requiredCPU, err := resource.ParseQuantity(req.cpu)
		if err != nil {
			result = append(result, err.Error())
			return result
		}
		cpu := n.Status.Capacity.Cpu()

		if cpu != nil && cpu.Cmp(requiredCPU) == -1 {
			msg := fmt.Sprintf("Insufficiant CPU on node %s, current: %s - required: %s", n.GetObjectMeta().GetName(), cpu.String(), requiredCPU.String())
			result = append(result, msg)
		}
	}

	if req.memorySize != "" {
		requiredMemory, err := resource.ParseQuantity(req.memorySize)
		if err != nil {
			result = append(result, err.Error())
			return result
		}
		memory := n.Status.Capacity.Memory()
		if memory != nil && memory.Cmp(requiredMemory) == -1 {
			msg := fmt.Sprintf("Insufficiant Memory on node %s, current: %s - required: %s", n.GetObjectMeta().GetName(), memory.String(), requiredMemory.String())
			result = append(result, msg)
		}
	}

	return result
}
