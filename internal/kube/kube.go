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
	"context"
	"os"
	"time"

	"github.com/codefresh-io/cli-v2/internal/log"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/apply"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

//go:generate mockgen -destination=./mocks/kube.go -package=mocks -source=./kube.go Factory

const (
	defaultPollInterval = time.Second * 2
	defaultPollTimeout  = time.Minute * 5
)

type (
	Factory interface {
		// KubernetesClientSet returns a new kubernetes clientset or error
		KubernetesClientSet() (kubernetes.Interface, error)

		// ToRESTConfig returns a rest Config object or error
		ToRESTConfig() (*restclient.Config, error)

		// Apply applies the provided manifests
		Apply(ctx context.Context, manifests []byte) error

		// Wait waits for all of the provided `Resources` to be ready by calling
		// the `WaitFunc` of each resource until all of them returns `true`
		Wait(context.Context, *WaitOptions) error
	}

	WaitFunc func(ctx context.Context, f Factory, ns, name string) (bool, error)

	Resource struct {
		Name      string
		Namespace string

		// WaitFunc will be called to check if the resources is ready. Should return (true, nil)
		// if the resources is ready, (false, nil) if the resource is not ready yet, or (false, err)
		// if some error occured (in that case the `Wait` will fail with that error).
		WaitFunc WaitFunc
	}

	DeleteOptions struct {
		LabelSelector   string
		ResourceTypes   []string
		Timeout         time.Duration
		WaitForDeletion bool
	}

	WaitOptions struct {
		// Inverval the duration between each iteration of calling all of the resources' `WaitFunc`s.
		Interval time.Duration

		// Timeout the max time to wait for all of the resources to be ready. If not all of the
		// resourecs are ready at time this will cause `Wait` to return an error.
		Timeout time.Duration

		// Resources the list of resources to wait for.
		Resources []Resource
	}

	factory struct {
		f cmdutil.Factory
	}
)

func AddFlags(flags *pflag.FlagSet) Factory {
	timeout := "0"
	kubeConfig := ""
	namespace := ""
	context := ""
	confFlags := &genericclioptions.ConfigFlags{
		Timeout:    &timeout,
		KubeConfig: &kubeConfig,
		Namespace:  &namespace,
		Context:    &context,
	}
	confFlags.AddFlags(flags)
	mvFlags := cmdutil.NewMatchVersionFlags(confFlags)

	return &factory{f: cmdutil.NewFactory(mvFlags)}
}

func (f *factory) KubernetesClientSet() (kubernetes.Interface, error) {
	return f.f.KubernetesClientSet()
}

func (f *factory) ToRESTConfig() (*restclient.Config, error) {
	return f.f.ToRESTConfig()
}

func (f *factory) Apply(ctx context.Context, manifests []byte) error {
	reader, buf, err := os.Pipe()
	if err != nil {
		return err
	}

	cmd := apply.NewCmdApply("apply", f.f, defaultIOStreams())

	stdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = stdin }()

	run := cmd.Run
	cmd.Run = nil
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		errc := make(chan error)
		go func() {
			if _, err = buf.Write(manifests); err != nil {
				errc <- err
			}
			if err = buf.Close(); err != nil {
				errc <- err
			}
			close(errc)
		}()

		run(cmd, args)

		return <-errc
	}
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	args := []string{"-f", "-", "--overwrite"}

	cmd.SetArgs(args)

	return cmd.ExecuteContext(ctx)
}

func (f *factory) Wait(ctx context.Context, opts *WaitOptions) error {
	itr := 0
	resources := map[*Resource]bool{}
	for i := range opts.Resources {
		resources[&opts.Resources[i]] = true
	}

	interval := defaultPollInterval
	timeout := defaultPollTimeout
	if opts.Interval > 0 {
		interval = opts.Interval
	}
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	return wait.PollImmediate(interval, timeout, func() (done bool, err error) {
		itr += 1
		allReady := true

		for r := range resources {
			lgr := log.G().WithFields(log.Fields{
				"itr":       itr,
				"name":      r.Name,
				"namespace": r.Namespace,
			})

			lgr.Debug("checking resource readiness")
			ready, err := r.WaitFunc(ctx, f, r.Namespace, r.Name)
			if err != nil {
				lgr.WithError(err).Debug("resource not ready")
				continue
			}

			if !ready {
				allReady = false
				lgr.Debug("resource not ready")
				continue
			}

			lgr.Debug("resource ready")
			delete(resources, r)
		}

		return allReady, nil
	})
}

func defaultIOStreams() genericclioptions.IOStreams {
	return genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
}
