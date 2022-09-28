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

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
)

type (
	RuntimeInstallOptions struct {
		KubeFactory        kube.Factory
		Namespace          string
		ContextUrl         string
		AccessMode         platmodel.AccessMode
		TunnelRegisterHost string
	}

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

func EnsureClusterRequirements(runtimeInstallOptions RuntimeInstallOptions, ctx context.Context) error {
	requirementsValidationErrorMessage := "cluster does not meet minimum requirements"
	namespace := runtimeInstallOptions.Namespace
	kubeFactory := runtimeInstallOptions.KubeFactory
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

	err = runNetworkTest(ctx, kubeFactory, runtimeInstallOptions.ContextUrl)
	if err != nil {
		return fmt.Errorf("cluster network tests failed: %w ", err)
	}

	log.G(ctx).Info("Network test finished successfully")

	if runtimeInstallOptions.AccessMode == platmodel.AccessModeTunnel {
		err = runTCPConnectionTest(&runtimeInstallOptions, ctx)
		if err != nil {
			return fmt.Errorf("cluster TCP connection tests failed: %w ", err)
		}

		log.G(ctx).Info("TCP connection test finished successfully")
	}
	return nil
}

func runTCPConnectionTest(runtimeInstallOptions *RuntimeInstallOptions, context context.Context) error {
	const tcpConnectionTestsTimeout = 120 * time.Second
	envVars := map[string]string{
		"TUNNEL_REGISTER_HOST": runtimeInstallOptions.TunnelRegisterHost,
	}
	env := prepareEnvVars(envVars)

	client, err := runtimeInstallOptions.KubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	job, err := launchJob(context, client, LaunchJobOptions{
		Namespace:     store.Get().DefaultNamespace,
		JobName:       &store.Get().TCPConnectionTesterName,
		Image:         &store.Get().TCPConnectionTesterImage,
		Env:           env,
		RestartPolicy: v1.RestartPolicyNever,
		BackOffLimit:  0,
	})
	if err != nil {
		return err
	}

	defer func() {
		err := deleteJob(context, client, job)
		if err != nil {
			log.G(context).Errorf("fail to delete tester pod: %s", err.Error())
		}
	}()

	log.G(context).Info("Running network test...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var podLastState *v1.Pod
	timeoutChan := time.After(tcpConnectionTestsTimeout)

Loop:
	for {
		select {
		case <-ticker.C:
			log.G(context).Debug("Waiting for TCP connection tester to finish")
			currentPod, err := getPodByJob(context, client, job)
			if err != nil {
				return err
			}

			if currentPod == nil {
				log.G(context).Debug("TCP connection tester pod: waiting for pod")
				continue
			}

			if len(currentPod.Status.ContainerStatuses) == 0 {
				log.G(context).Debug("TCP connection tester pod: creating container")
				continue
			}

			state := currentPod.Status.ContainerStatuses[0].State
			if state.Running != nil {
				log.G(context).Debug("TCP connection tester pod: running")
			}

			if state.Waiting != nil {
				log.G(context).Debug("TCP connection tester pod: waiting")
			}

			if state.Terminated != nil {
				log.G(context).Debug("TCP connection tester pod: terminated")
				podLastState = currentPod
				break Loop
			}
		case <-timeoutChan:
			return fmt.Errorf("TCP connection test timeout reached!")
		}
	}

	return checkPodLastState(context, client, podLastState)
}

func GetClusterSecret(ctx context.Context, kubeFactory kube.Factory, namespace string, name string) (*v1.Secret, error) {
	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return nil, fmt.Errorf("cannot create kubernetes clientset: %w", err)
	}

	var (
		res  *v1.Secret
		cont string
	)
	for res == nil {
		secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "argocd.argoproj.io/secret-type=cluster",
			Limit:         10,
			Continue:      cont,
		})
		if err != nil {
			return nil, err
		}

		for _, secret := range secrets.Items {
			if string(secret.Data["name"]) == name {
				res = &secret
				break
			}
		}

		cont = secrets.Continue
	}

	return res, nil
}

func WaitForJob(ctx context.Context, f kube.Factory, ns, jobName string) error {
	var attempt int32
	var jobErr error
	_ = f.Wait(ctx, &kube.WaitOptions{
		Interval: time.Second * 5,
		Timeout:  time.Minute,
		Resources: []kube.Resource{
			{
				Name:      jobName,
				Namespace: ns,
				WaitFunc: func(ctx context.Context, f kube.Factory, ns, name string) (bool, error) {
					cs, err := f.KubernetesClientSet()
					if err != nil {
						return false, err
					}

					j, err := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}

					totalRetries := *j.Spec.BackoffLimit + 1
					if j.Status.Failed > attempt {
						attempt = j.Status.Failed
						log.G(ctx).Warnf("Attempt #%d/%d failed:", attempt, totalRetries)
						printJobLogs(ctx, cs, j)
					} else if j.Status.Succeeded == 1 {
						attempt += 1
						log.G(ctx).Infof("Attempt #%d/%d succeeded:", attempt, totalRetries)
						printJobLogs(ctx, cs, j)
					}

					for _, cond := range j.Status.Conditions {
						if cond.Type == batchv1.JobFailed {
							jobErr = fmt.Errorf("add-cluster-job failed after %d attempt(s)", j.Status.Failed)
							break
						}
					}

					return j.Status.Succeeded == 1 || j.Status.Failed == totalRetries, jobErr
				},
			},
		},
	})
	return jobErr
}

func printJobLogs(ctx context.Context, client kubernetes.Interface, job *batchv1.Job) {
	p, err := getPodByJob(ctx, client, job)
	if err != nil {
		log.G(ctx).Errorf("Failed getting pod for job: $s", err.Error())
		return
	}

	logs, err := getPodLogs(ctx, client, p.GetNamespace(), p.GetName())
	if err != nil {
		log.G(ctx).Errorf("Failed getting logs for pod: $s", err.Error())
		return
	}

	fmt.Printf("=====\n%s\n=====\n\n", logs)
}

func runNetworkTest(ctx context.Context, kubeFactory kube.Factory, urls ...string) error {
	const networkTestsTimeout = 120 * time.Second

	envVars := map[string]string{
		"URLS":       strings.Join(urls, ","),
		"IN_CLUSTER": "1",
	}
	env := prepareEnvVars(envVars)

	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	job, err := launchJob(ctx, client, LaunchJobOptions{
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

	defer func() {
		err := deleteJob(ctx, client, job)
		if err != nil {
			log.G(ctx).Errorf("fail to delete tester pod: %s", err.Error())
		}
	}()

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
			currentPod, err := getPodByJob(ctx, client, job)
			if err != nil {
				return err
			}

			if currentPod == nil {
				log.G(ctx).Debug("Network tester pod: waiting for pod")
				continue
			}

			if len(currentPod.Status.ContainerStatuses) == 0 {
				log.G(ctx).Debug("Network tester pod: creating container")
				continue
			}

			state := currentPod.Status.ContainerStatuses[0].State
			if state.Running != nil {
				log.G(ctx).Debug("Network tester pod: running")
			}

			if state.Waiting != nil {
				log.G(ctx).Debug("Network tester pod: waiting")
			}

			if state.Terminated != nil {
				log.G(ctx).Debug("Network tester pod: terminated")
				podLastState = currentPod
				break Loop
			}
		case <-timeoutChan:
			return fmt.Errorf("network test timeout reached!")
		}
	}

	return checkPodLastState(ctx, client, podLastState)
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

func checkPodLastState(ctx context.Context, client kubernetes.Interface, pod *v1.Pod) error {
	terminated := pod.Status.ContainerStatuses[0].State.Terminated
	if terminated.ExitCode != 0 {
		logs, err := getPodLogs(ctx, client, pod.Namespace, pod.Name)
		if err != nil {
			log.G(ctx).Errorf("Failed getting logs from network-tester pod: $s", err.Error())
		} else {
			log.G(ctx).Error(logs)
		}

		terminationMessage := strings.Trim(terminated.Message, "\n")
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

func launchJob(ctx context.Context, client kubernetes.Interface, opts LaunchJobOptions) (*batchv1.Job, error) {
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

	return client.BatchV1().Jobs(opts.Namespace).Create(ctx, jobSpec, metav1.CreateOptions{})
}

func deleteJob(ctx context.Context, client kubernetes.Interface, job *batchv1.Job) error {
	err := client.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("fail to delete job resource \"%s\": %s", job.Name, err.Error())
	}

	err = client.CoreV1().Pods(job.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{
		LabelSelector: "controller-uid=" + job.GetLabels()["controller-uid"],
	})
	if err != nil {
		return fmt.Errorf("fail to delete tester pod: %s", err.Error())
	}

	return nil
}

func getPodByJob(ctx context.Context, client kubernetes.Interface, job *batchv1.Job) (*v1.Pod, error) {
	pods, err := client.CoreV1().Pods(job.GetNamespace()).List(ctx, metav1.ListOptions{
		LabelSelector: "controller-uid=" + job.Spec.Selector.MatchLabels["controller-uid"],
	})
	if err != nil {
		return nil, err
	}

	if len(pods.Items) == 0 {
		return nil, nil
	}

	return &pods.Items[0], nil
}

func getPodLogs(ctx context.Context, client kubernetes.Interface, namespace, name string) (string, error) {
	req := client.CoreV1().Pods(namespace).GetLogs(name, &v1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get network-tester pod logs: %w", err)
	}
	defer podLogs.Close()

	logsBuf := new(bytes.Buffer)
	_, err = io.Copy(logsBuf, podLogs)
	if err != nil {
		return "", fmt.Errorf("failed to read network-tester pod logs: %w", err)
	}

	return strings.Trim(logsBuf.String(), "\n"), nil
}

func CheckNamespaceExists(ctx context.Context, namespace string, kubeFactory kube.Factory) (bool, error) {
	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get namespace %s: %w", namespace, err)
	}

	return true, nil
}
