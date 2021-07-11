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

package store

import (
	"fmt"
	"runtime"
	"time"
)

var s Store

var (
	binaryName                = "cli-v2"
	version                   = "v99.99.99"
	buildDate                 = ""
	gitCommit                 = ""
	RuntimeDefURL             = "manifests/runtime.yaml"
	ArgoCDManifestsURL        = "manifests/argo-cd"
	ArgoEventsManifestsURL    = "manifests/argo-events"
	ArgoRolloutsManifestsURL  = "manifests/argo-rollouts"
	ArgoWorkflowsManifestsURL = "manifests/argo-workflows"
	ComponentsReporterURL     = "manifests/components-reporter"
)

type Version struct {
	Version    string
	BuildDate  string
	GitCommit  string
	GoVersion  string
	GoCompiler string
	Platform   string
}

type Store struct {
	ArgoCDManifestsURL        string
	ArgoEventsManifestsURL    string
	ArgoRolloutsManifestsURL  string
	ArgoWorkflowsManifestsURL string
	BinaryName                string
	CFComponentType           string
	CFRuntimeType             string
	CFTokenSecret             string
	CFTokenSecretKey          string
	CFType                    string
	ComponentsReporterName    string
	ComponentsReporterSA      string
	ComponentsReporterURL     string
	DefaultAPI                string
	EventBusName              string
	EventReportingEndpoint    string
	GitSourceName             string
	RuntimeDefURL             string
	Version                   Version
	WaitTimeout               time.Duration
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.ArgoCDManifestsURL = ArgoCDManifestsURL
	s.ArgoEventsManifestsURL = ArgoEventsManifestsURL
	s.ArgoRolloutsManifestsURL = ArgoRolloutsManifestsURL
	s.ArgoWorkflowsManifestsURL = ArgoWorkflowsManifestsURL
	s.BinaryName = binaryName
	s.CFComponentType = "component"
	s.CFRuntimeType = "runtime"
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.CFType = "codefresh.io/type"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
	s.ComponentsReporterURL = ComponentsReporterURL
	s.DefaultAPI = "https://g.codefresh.io"
	s.EventBusName = "codefresh-eventbus"
	s.EventReportingEndpoint = "/argo/api/events"
	s.GitSourceName = "default-git-source"
	s.RuntimeDefURL = RuntimeDefURL
	s.WaitTimeout = 5 * time.Minute
	initVersion()
}

func initVersion() {
	s.Version.Version = version
	s.Version.BuildDate = buildDate
	s.Version.GitCommit = gitCommit
	s.Version.GoVersion = runtime.Version()
	s.Version.GoCompiler = runtime.Compiler
	s.Version.Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
