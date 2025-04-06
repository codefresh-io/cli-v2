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

package util

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/reporter"
	"github.com/codefresh-io/cli-v2/internal/store"

	v1 "github.com/codefresh-io/go-sdk/pkg/rest"
	"github.com/pkg/browser"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type RetryOptions struct {
	Func    func() error
	Retries int
	Sleep   time.Duration
}

const (
	yamlSeperator = "\n---\n"
	indentation   = "    "
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

func kubeConfig(kubeconfig string) *clientcmdapi.Config {
	configAccess := clientcmd.NewDefaultPathOptions()
	if kubeconfig != "" {
		configAccess.GlobalFile = kubeconfig
	}
	conf, err := configAccess.GetStartingConfig()
	Die(err, "failed reading kubeconfig file")
	return conf
}

type kubeContext struct {
	Name    string
	Current bool
}

func KubeContexts(kubeconfig string) []kubeContext {
	conf := kubeConfig(kubeconfig)
	contexts := make([]kubeContext, len(conf.Contexts))
	i := 0
	for key := range conf.Contexts {
		contexts[i] = kubeContext{
			Name:    key,
			Current: key == conf.CurrentContext,
		}
		i += 1
	}

	sort.SliceStable(contexts, func(i, j int) bool {
		c1 := contexts[i]
		if c1.Current {
			return true
		}

		c2 := contexts[j]
		if c2.Current {
			return false
		}

		return c1.Name < c2.Name
	})

	return contexts
}

func CheckExistingContext(contextName, kubeconfig string) bool {
	for _, context := range KubeContexts(kubeconfig) {
		if context.Name == contextName {
			return true
		}
	}

	return false
}

func KubeCurrentContextName(kubeconfig string) string {
	conf := kubeConfig(kubeconfig)
	return conf.CurrentContext
}

func CurrentAccount(user *v1.User) (string, error) {
	for i := range user.Accounts {
		if user.Accounts[i].Name == user.ActiveAccountName {
			return user.Accounts[i].ID, nil
		}
	}
	return "", fmt.Errorf("account id for \"%s\" not found", user.ActiveAccountName)
}

func OpenBrowserForGitLogin(ingressHost string, user string, account string) error {
	var b bytes.Buffer
	if !strings.HasPrefix(ingressHost, "http") {
		b.WriteString("https://")
	}
	b.WriteString(ingressHost)
	b.WriteString("/app-proxy/api/git-auth/github?userId=" + user + "&accountId=" + account)

	url, err := url.Parse(b.String())
	if err != nil {
		return err
	}

	err = browser.OpenURL(url.String())
	if err != nil {
		return err
	}

	fmt.Println("Follow instructions in web browser")
	time.Sleep(2 * time.Second)

	return nil
}

func KubeServerByContextName(contextName, kubeconfig string) (string, error) {
	conf := kubeConfig(kubeconfig)
	if contextName == "" {
		contextName = conf.CurrentContext
	}

	context := conf.Contexts[contextName]
	if context == nil {
		return "", fmt.Errorf("kubeconfig file missing context \"%s\"", contextName)
	}

	cluster := conf.Clusters[context.Cluster]
	if cluster == nil {
		return "", fmt.Errorf("kubeconfig file missing cluster \"%s\"", context.Cluster)
	}

	return cluster.Server, nil
}

func reportCancel(status reporter.CliStepStatus) {
	reporter.G().ReportStep(reporter.CliStepData{
		Step:        reporter.SIGNAL_TERMINATION,
		Status:      status,
		Description: "Cancelled by an external signal",
		Err:         nil,
	})
}

func StringIndexOf(slice []string, val string) int {
	for i, item := range slice {
		if item == val {
			return i
		}
	}

	return -1
}

func ReverseMap[K, V comparable](gitProviders map[K]V) map[V]K {
	reversedMap := map[V]K{}
	for key, value := range gitProviders {
		reversedMap[value] = key
	}
	return reversedMap
}

// JoinManifests concats all of the provided yaml manifests with a yaml separator.
func JoinManifests(manifests ...[]byte) []byte {
	res := make([]string, 0, len(manifests))
	for _, m := range manifests {
		if m == nil {
			continue
		}
		res = append(res, string(m))
	}
	return []byte(strings.Join(res, yamlSeperator))
}

func SplitManifests(manifests []byte) [][]byte {
	str := string(manifests)
	stringManifests := strings.Split(str, yamlSeperator)
	res := make([][]byte, 0, len(stringManifests))
	for _, m := range stringManifests {
		res = append(res, []byte(m))
	}
	return res
}

// MustParseDuration parses the given string as "time.Duration", or panic.
func MustParseDuration(dur string) time.Duration {
	d, err := time.ParseDuration(dur)
	Die(err)
	return d
}
