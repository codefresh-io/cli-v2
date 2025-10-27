// Copyright 2025 The Codefresh Authors.
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

	"github.com/codefresh-io/cli-v2/internal/kube"
	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/util"

	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func WaitForJob(ctx context.Context, kubeFactory kube.Factory, ns, jobName string) error {
	var attempt int32
	var jobErr error
	_ = kubeFactory.Wait(ctx, &kube.WaitOptions{
		Interval: time.Second * 5,
		Timeout:  time.Minute,
		Resources: []kube.Resource{
			{
				Name:      jobName,
				Namespace: ns,
				WaitFunc: func(ctx context.Context, kubeFactory kube.Factory, ns, name string) (bool, error) {
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
	defer func() { _ = podLogs.Close() }()

	logsBuf := new(bytes.Buffer)
	_, err = io.Copy(logsBuf, podLogs)
	if err != nil {
		return "", fmt.Errorf("failed to read network-tester pod logs: %w", err)
	}

	return strings.Trim(logsBuf.String(), "\n"), nil
}

func GetClientSet(kubeFactory kube.Factory) (kubernetes.Interface, error) {
	cs, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		if strings.Contains(err.Error(), "exec plugin: invalid apiVersion") {
			return nil, errors.New("Kubeconfig user entry is using an invalid API version client.authentication.k8s.io/v1alpha1.\nSee details at https://support.codefresh.io/hc/en-us/articles/6947789386652-Failure-to-perform-actions-on-your-selected-Kubernetes-context")
		}

		return nil, fmt.Errorf("failed to build kubernetes clientset: %w", err)
	}

	return cs, nil
}

func GetClientSetOrDie(kubeFactory kube.Factory) kubernetes.Interface {
	cs, err := GetClientSet(kubeFactory)
	util.Die(err)
	return cs
}

func GetValueFromSecret(ctx context.Context, kubeFactory kube.Factory, namespace, name, key string) (string, error) {
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
