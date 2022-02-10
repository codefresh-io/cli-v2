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

package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/briandowns/spinner"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/reporter"
	"github.com/codefresh-io/cli-v2/pkg/store"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	indentation = "    "
)

var (
	spinnerCharSet    = spinner.CharSets[26]
	spinnerDuration   = time.Millisecond * 500
	appsetFieldRegexp = regexp.MustCompile(`[\./]`)
)

// ContextWithCancelOnSignals returns a context that is canceled when one of the specified signals
// are received
func ContextWithCancelOnSignals(ctx context.Context, sigs ...os.Signal) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, sigs...)

	go func() {
		cancels := 0
		for {
			s := <-sig
			cancels++
			if cancels == 1 {
				log.G(ctx).Printf("got signal: %s", s)
				reportCancel(reporter.CANCELED)
				cancel()
			} else {
				reporter.G().Close(reporter.ABRUPTLY_CANCELED, nil)
				log.G(ctx).Printf("forcing exit")
				os.Exit(1)
			}
		}
	}()

	return ctx
}

// Die panics it the error is not nil. If a cause string is provided it will
// be displayed in the error message.
func Die(err error, cause ...string) {
	if err != nil {
		if len(cause) > 0 {
			panic(fmt.Errorf("%s: %w", cause[0], err))
		}
		panic(err)
	}
}

// WithSpinner create a spinner that prints a message and canceled if the
// given context is canceled or the returned stop function is called.
func WithSpinner(ctx context.Context, msg ...string) func() {
	if os.Getenv("NO_COLOR") != "" { // https://no-color.org/
		log.G(ctx).Info(msg)
		return func() {}
	}

	ctx, cancel := context.WithCancel(ctx)
	s := spinner.New(
		spinnerCharSet,
		spinnerDuration,
	)
	if len(msg) > 0 {
		s.Prefix = msg[0]
	}
	go func() {
		s.Start()
		<-ctx.Done()
		s.Stop()
		fmt.Println("")
	}()

	return func() {
		cancel()
		// wait just enough time to prevent logs jumbling between spinner and main flow
		time.Sleep(time.Millisecond * 100)
	}
}

// Doc returns a string where all the '<BIN>' are replaced with the binary name
// and all the '\t' are replaced with a uniformed indentation using space.
func Doc(doc string) string {
	doc = strings.ReplaceAll(doc, "<BIN>", store.Get().BinaryName)
	doc = strings.ReplaceAll(doc, "\t", indentation)
	return doc
}

type AsyncRunner struct {
	wg   sync.WaitGroup
	errC chan error
}

// NewAsyncRunner initializes a new AsyncRunner that can run up to
// n async operations.
func NewAsyncRunner(n int) *AsyncRunner {
	return &AsyncRunner{
		wg:   sync.WaitGroup{},
		errC: make(chan error, n),
	}
}

// Run runs another async operation
func (ar *AsyncRunner) Run(f func() error) {
	ar.wg.Add(1)
	go func() {
		defer ar.wg.Done()
		if err := f(); err != nil {
			ar.errC <- err
		}
	}()
}

// Wait waits for all async operations to finish and returns an error
// if one of the async operations returned an error, otherwise, returns
// nil.
func (ar *AsyncRunner) Wait() error {
	ar.wg.Wait()
	select {
	case err := <-ar.errC:
		return err
	default:
		return nil
	}
}

func EscapeAppsetFieldName(field string) string {
	return appsetFieldRegexp.ReplaceAllString(field, "_")
}

func CurrentServer() (string, error) {
	configAccess := clientcmd.NewDefaultPathOptions()
	conf, err := configAccess.GetStartingConfig()
	if err != nil {
		return "", err
	}

	server := conf.Clusters[conf.Contexts[conf.CurrentContext].Cluster].Server
	return server, nil
}

func DecorateErrorWithDocsLink(err error, link ...string) error {
	if len(link) == 0 {
		return fmt.Errorf("%s\nfor more information: %s", err.Error(), store.Get().DocsLink)
	}

	return fmt.Errorf("%s\nfor more information: %s", err.Error(), link[0])
}

func reportCancel(status reporter.CliStepStatus) {
	reporter.G().ReportStep(reporter.CliStepData{
		Step:        reporter.SIGNAL_TERMINATION,
		Status:      status,
		Description: "Cancelled by an external signal",
		Err:         nil,
	})
}

func TestNetwork(ctx context.Context, kubeFactory kube.Factory, urls string) error {
	const networkTestsTimeout = 120 * time.Second
	var testerPodName string

	envVars := map[string]string{
		"URLS": urls,
		"IN_CLUSTER": "1",
	}
	env := prepareEnvVars(envVars)

	client, err := kubeFactory.KubernetesClientSet()
	if err != nil {
		return fmt.Errorf("fail to create kubernetes client: %w", err)
	}

	err = kubeutil.LaunchJob(kubeutil.LaunchJobOptions{
		Ctx:           ctx,
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

	defer func() {
		deferErr := client.BatchV1().Jobs(store.Get().DefaultNamespace).Delete(ctx, store.Get().NetworkTesterName, metav1.DeleteOptions{})
		if deferErr != nil {
			log.G(ctx).Error("fail to delete job resource '%s': %s", store.Get().NetworkTesterName, deferErr.Error())
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
			return fmt.Errorf("Network test timeout reached!")
		}
	}

	defer func() {
		deferErr := client.CoreV1().Pods(store.Get().DefaultNamespace).Delete(ctx, testerPodName, metav1.DeleteOptions{})
		if deferErr != nil {
			log.G(ctx).Error("fail to delete tester pod '%s': %s", testerPodName, deferErr.Error())
		}
	}()
	
	return checkPodLastState(ctx, client, testerPodName,podLastState)
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

	log.G(ctx).Info("Network test finished successfully")

	return nil
}

