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

package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
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

	LaunchJobOptions struct {
		Client        kubernetes.Interface
		Namespace     string
		JobName       *string
		Image         *string
		Env           []v1.EnvVar
		RestartPolicy v1.RestartPolicy
		BackOffLimit  int32
	}
)

func EnsureClusterRequirements(ctx context.Context, kubeFactory kube.Factory, namespace string, contextUrl string) error {
	requirementsValidationErrorMessage := "cluster does not meet minimum requirements"
	var specificErrorMessages []string

	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("cannot create kubernetes clientset: %w", err)
	}

	kubeVersion, err := client.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to check the cluster's version: %w", err)
	}

	minDelta := version.CompareKubeAwareVersionStrings(store.Get().MinKubeVersion, kubeVersion.String())
	maxDelta := version.CompareKubeAwareVersionStrings(store.Get().MaxKubeVersion, kubeVersion.String())

	if minDelta < 0 || maxDelta > 0 {
		return fmt.Errorf("%s: cluster's server version must be between %s and %s", requirementsValidationErrorMessage, store.Get().MinKubeVersion, store.Get().MaxKubeVersion)
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

	err = runNetworkTest(ctx, kubeFactory, contextUrl)
	if err != nil {
		return fmt.Errorf("cluster network tests failed: %w ", err)
	}
	
	log.G(ctx).Info("Network test finished successfully")

	return nil
}

func runNetworkTest(ctx context.Context, kubeFactory kube.Factory, urls ...string) error {
	const networkTestsTimeout = 120 * time.Second
	var testerPodName string

	envVars := map[string]string{
		"URLS":       strings.Join(urls, ","),
		"IN_CLUSTER": "1",
	}
	env := prepareEnvVars(envVars)

	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	err = LaunchJob(ctx, LaunchJobOptions{
		Client:        client,
		Namespace:     store.Get().DefaultNamespace,
		JobName:       &store.Get().NetworkTesterName,
		Image:         &store.Get().NetworkTesterImage,
		Env:           env,
		RestartPolicy: v1.RestartPolicyNever,
		BackOffLimit:  0,
	})
	if err != nil {
		return err
	}

	defer func(name *string) {
		deferErr := client.BatchV1().Jobs(store.Get().DefaultNamespace).Delete(ctx, store.Get().NetworkTesterName, metav1.DeleteOptions{})
		if deferErr != nil {
			log.G(ctx).Errorf("fail to delete job resource '%s': %s", store.Get().NetworkTesterName, deferErr.Error())
		}

		deferErr = client.CoreV1().Pods(store.Get().DefaultNamespace).Delete(ctx, *name, metav1.DeleteOptions{})
		if deferErr != nil {
			log.G(ctx).Errorf("fail to delete tester pod '%s': %s", testerPodName, deferErr.Error())
		}
	}(&testerPodName)

	log.G(ctx).Info("Running network test...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var podLastState *v1.Pod
	timeoutChan := time.After(networkTestsTimeout)

Loop:
	for {
		select {
		case <-ticker.C:
			log.G(ctx).Debug("Waiting for network tester to finish")

			if testerPodName == "" {
				testerPodName, err = getTesterPodName(ctx, client)
				if err != nil {
					return err
				}
			}

			pod, err := client.CoreV1().Pods(store.Get().DefaultNamespace).Get(ctx, testerPodName, metav1.GetOptions{})
			if err != nil {
				if statusError, errIsStatusError := err.(*kerrors.StatusError); errIsStatusError {
					if statusError.ErrStatus.Reason == metav1.StatusReasonNotFound {
						log.G(ctx).Debug("Network tester pod not found")
					}
				}
			}
			if len(pod.Status.ContainerStatuses) == 0 {
				log.G(ctx).Debug("Network tester pod: creating container")
				continue
			}
			if pod.Status.ContainerStatuses[0].State.Running != nil {
				log.G(ctx).Debug("Network tester pod: running")
			}
			if pod.Status.ContainerStatuses[0].State.Waiting != nil {
				log.G(ctx).Debug("Network tester pod: waiting")
			}
			if pod.Status.ContainerStatuses[0].State.Terminated != nil {
				log.G(ctx).Debug("Network tester pod: terminated")
				podLastState = pod
				break Loop
			}
		case <-timeoutChan:
			return fmt.Errorf("network test timeout reached!")
		}
	}

	return checkPodLastState(ctx, client, testerPodName, podLastState)
}

func prepareEnvVars(vars map[string]string) []v1.EnvVar {
	var env []v1.EnvVar

	for key, value := range vars {
		env = append(env, v1.EnvVar{
			Name:  key,
			Value: value,
		})
	}

	return env
}

func getTesterPodName(ctx context.Context, client kubernetes.Interface) (string, error) {
	pods, err := client.CoreV1().Pods(store.Get().DefaultNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get pods from cluster: %w", err)
	}

	for _, pod := range pods.Items {
		if pod.ObjectMeta.GenerateName == store.Get().NetworkTesterGenerateName {
			return pod.ObjectMeta.Name, nil
		}
	}

	return "", nil
}

func checkPodLastState(ctx context.Context, client kubernetes.Interface, name string, podLastState *v1.Pod) error {
	req := client.CoreV1().Pods(store.Get().DefaultNamespace).GetLogs(name, &v1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get network-tester pod logs: %w", err)
	}
	defer podLogs.Close()

	logsBuf := new(bytes.Buffer)
	_, err = io.Copy(logsBuf, podLogs)
	if err != nil {
		return fmt.Errorf("Failed to read network-tester pod logs: %w", err)
	}
	logs := strings.Trim(logsBuf.String(), "\n")
	log.G(ctx).Debug(logs)

	if podLastState.Status.ContainerStatuses[0].State.Terminated.ExitCode != 0 {
		terminationMessage := strings.Trim(podLastState.Status.ContainerStatuses[0].State.Terminated.Message, "\n")
		return fmt.Errorf("Network test failed with: %s", terminationMessage)
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

func LaunchJob(ctx context.Context, opts LaunchJobOptions) error {
	jobs := opts.Client.BatchV1().Jobs(opts.Namespace)

	jobSpec := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *opts.JobName,
			Namespace: opts.Namespace,
		},
		Spec: batchv1.JobSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  *opts.JobName,
							Image: *opts.Image,
							Env:   opts.Env,
						},
					},
					RestartPolicy: opts.RestartPolicy,
				},
			},
			BackoffLimit: &opts.BackOffLimit,
		},
	}

	_, err := jobs.Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create K8s job '%s' : %w", *opts.JobName, err)
	}

	return nil
}
