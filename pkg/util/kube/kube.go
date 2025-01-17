// Copyright 2024 The Codefresh Authors.
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
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"

	"github.com/Masterminds/semver/v3"
	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	aputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type (
	ClusterRequirementsOptions struct {
		KubeFactory        apkube.Factory
		Namespace          string
		ContextUrl         string
		AccessMode         platmodel.AccessMode
		TunnelRegisterHost string
		IsCustomInstall    bool
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
		ContainerName string
		GenerateName  string
		Image         string
		Env           []v1.EnvVar
		RestartPolicy v1.RestartPolicy
		BackOffLimit  int32
	}
)

func EnsureClusterRequirements(ctx context.Context, opts ClusterRequirementsOptions) error {
	requirementsValidationErrorMessage := "cluster does not meet minimum requirements"
	namespace := opts.Namespace
	kubeFactory := opts.KubeFactory
	var specificErrorMessages []string

	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return err
	}

	kubeVersion, err := client.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to check the cluster's version: %w", err)
	}

	v := semver.MustParse(kubeVersion.String())
	if !store.Get().KubeVersionConstrint.Check(v) {
		return fmt.Errorf("%s: cluster's server version must match %s", requirementsValidationErrorMessage, store.Get().KubeVersionConstrint)
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

	if opts.IsCustomInstall {
		return nil
	}

	err = runNetworkTest(ctx, kubeFactory, opts.ContextUrl)
	if err != nil {
		return fmt.Errorf("cluster network tests failed: %w ", err)
	}

	log.G(ctx).Info("Network test finished successfully")

	if opts.AccessMode == platmodel.AccessModeTunnel {
		err = runTCPConnectionTest(ctx, &opts)
		if err != nil {
			return fmt.Errorf("cluster TCP connection tests failed: %w ", err)
		}

		log.G(ctx).Info("TCP connection test finished successfully")
	}

	return nil
}

func runTCPConnectionTest(ctx context.Context, runtimeInstallOptions *ClusterRequirementsOptions) error {
	const tcpConnectionTestsTimeout = 120 * time.Second
	envVars := map[string]string{
		"TUNNEL_REGISTER_HOST": runtimeInstallOptions.TunnelRegisterHost,
	}
	env := prepareEnvVars(envVars)

	client, err := GetClientSet(runtimeInstallOptions.KubeFactory)
	if err != nil {
		return err
	}

	job, err := launchJob(ctx, client, LaunchJobOptions{
		Namespace:     store.Get().DefaultNamespace,
		ContainerName: store.Get().TCPConnectionTesterName,
		GenerateName:  store.Get().TCPConnectionTesterGenerateName,
		Image:         store.Get().NetworkTesterImage,
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

	log.G(ctx).Info("Running TCP connection test...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeoutChan := time.After(tcpConnectionTestsTimeout)
	podLastState, err := handleJobPodStates(ctx, client, job, ticker, timeoutChan)
	if err != nil {
		return err
	}
	return checkPodLastState(ctx, client, podLastState)
}

func GetClusterSecret(ctx context.Context, kubeFactory apkube.Factory, namespace string, name string) (*v1.Secret, error) {
	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return nil, err
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

func WaitForJob(ctx context.Context, kubeFactory apkube.Factory, ns, jobName string) error {
	var attempt int32
	var jobErr error
	_ = kubeFactory.Wait(ctx, &apkube.WaitOptions{
		Interval: time.Second * 5,
		Timeout:  time.Minute,
		Resources: []apkube.Resource{
			{
				Name:      jobName,
				Namespace: ns,
				WaitFunc: func(ctx context.Context, kubeFactory apkube.Factory, ns, name string) (bool, error) {
					cs, err := GetClientSet(kubeFactory)
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

func runNetworkTest(ctx context.Context, kubeFactory apkube.Factory, urls ...string) error {
	const networkTestsTimeout = 120 * time.Second

	envVars := map[string]string{
		"URLS":       strings.Join(urls, ","),
		"IN_CLUSTER": "1",
	}
	env := prepareEnvVars(envVars)

	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return err
	}

	job, err := launchJob(ctx, client, LaunchJobOptions{
		Namespace:     store.Get().DefaultNamespace,
		ContainerName: store.Get().NetworkTesterName,
		GenerateName:  store.Get().NetworkTesterGenerateName,
		Image:         store.Get().NetworkTesterImage,
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
	timeoutChan := time.After(networkTestsTimeout)
	podLastState, err := handleJobPodStates(ctx, client, job, ticker, timeoutChan)
	if err != nil {
		return err
	}
	return checkPodLastState(ctx, client, podLastState)
}

func handleJobPodStates(ctx context.Context, client kubernetes.Interface, job *batchv1.Job, ticker *time.Ticker, timeoutChan <-chan time.Time) (*v1.Pod, error) {
	var podLastState *v1.Pod
Loop:
	for {
		select {
		case <-ticker.C:
			log.G(ctx).Debug("Waiting for network tester to finish")
			currentPod, err := getPodByJob(ctx, client, job)
			if err != nil {
				return nil, err
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
			return nil, fmt.Errorf("network test timeout reached!")
		}
	}
	return podLastState, nil
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
			GenerateName: opts.GenerateName,
			Namespace:    opts.Namespace,
		},
		Spec: batchv1.JobSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  opts.ContainerName,
							Image: opts.Image,
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
		LabelSelector: "controller-uid=" + job.Labels["controller-uid"],
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

func CheckNamespaceExists(ctx context.Context, namespace string, kubeFactory apkube.Factory) (bool, error) {
	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return false, err
	}

	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get namespace %s: %w", namespace, err)
	}

	return true, nil
}

func DeleteSecretWithFinalizer(ctx context.Context, kubeFactory apkube.Factory, secret *v1.Secret) error {
	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return err
	}

	secret.Finalizers = nil
	secret, err = client.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to remove finalizers from secret %s", secret.Name)
	}

	err = client.CoreV1().Secrets(secret.Namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}

	return err
}

func GetSecretsWithLabel(ctx context.Context, kubeFactory apkube.Factory, namespace, label string) (*v1.SecretList, error) {
	client, err := GetClientSet(kubeFactory)
	if err != nil {
		return nil, err
	}

	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secrets, nil
}

func GetClientSet(kubeFactory apkube.Factory) (kubernetes.Interface, error) {
	cs, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		if strings.Contains(err.Error(), "exec plugin: invalid apiVersion") {
			return nil, errors.New("Kubeconfig user entry is using an invalid API version client.authentication.k8s.io/v1alpha1.\nSee details at https://support.codefresh.io/hc/en-us/articles/6947789386652-Failure-to-perform-actions-on-your-selected-Kubernetes-context")
		}

		return nil, fmt.Errorf("failed to build kubernetes clientset: %w", err)
	}

	return cs, nil
}

func GetClientSetOrDie(kubeFactory apkube.Factory) kubernetes.Interface {
	cs, err := GetClientSet(kubeFactory)
	aputil.Die(err)
	return cs
}

func GetValueFromSecret(ctx context.Context, kubeFactory apkube.Factory, namespace, name, key string) (string, error) {
	cs := GetClientSetOrDie(kubeFactory)
	secret, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed reading secret \"%s\": %w", name, err)
	}

	data, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret \"%s\" does not contain key \"%s\"", name, key)
	}

	value := string(data)
	if value == "" {
		return "", fmt.Errorf("secret \"%s\" key \"%s\" is an empty string", name, key)
	}

	return value, nil
}

func GetIngressClass(ctx context.Context, kubeFactory apkube.Factory, name string) (*netv1.IngressClass, error) {
	cs := GetClientSetOrDie(kubeFactory)
	return cs.NetworkingV1().IngressClasses().Get(ctx, name, metav1.GetOptions{})
}

func GetDynamicClientOrDie(kubeFactory apkube.Factory) dynamic.Interface {
	restConfig, err := kubeFactory.ToRESTConfig()
	if err != nil {
		panic(err)
	}

	return dynamic.NewForConfigOrDie(restConfig)
}
