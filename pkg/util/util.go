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
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"

	"github.com/briandowns/spinner"
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
				cancel()
			} else {
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
