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

	"github.com/Masterminds/semver/v3"
)

var s Store

var (
	binaryName    = "cli-v2"
	version       = "v99.99.99"
	buildDate     = ""
	gitCommit     = ""
	maxDefVersion = "1.0.0"
	RuntimeDefURL = "manifests/runtime.yaml"
)

type Version struct {
	Version    *semver.Version
	BuildDate  string
	GitCommit  string
	GoVersion  string
	GoCompiler string
	Platform   string
}

type Store struct {
	ArgoCDServerName       string
	ArgoCDTokenKey         string
	ArgoCDTokenSecret      string
	ArgoWFServiceName      string
	ArgoWFServicePort      int32
	BinaryName             string
	Codefresh              string
	CFComponentType        string
	CFGitSourceType        string
	CFRuntimeDefType       string
	CFRuntimeType          string
	CFTokenSecret          string
	CFTokenSecretKey       string
	CodefreshCM            string
	CodefreshSA            string
	ComponentsReporterName string
	ComponentsReporterSA   string
	ComponentsReporterURL  string
	DefaultAPI             string
	EventBusName           string
	EventReportingEndpoint string
	EventsReporterName     string
	GitSourceName          string
	IngressName            string
	IngressPath            string
	LabelKeyCFType         string
	MaxDefVersion          *semver.Version
	RuntimeDefURL          string
	RuntimeFilename        string
	Version                Version
	WaitTimeout            time.Duration
	MarketplaceGitSourceName string
	MarketplaceRepo			string
	MarketplacePluginsPath  string

	WorkflowName           string
	WorkflowReporterName   string
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.ArgoCDServerName = "argocd-server"
	s.ArgoCDTokenKey = "token"
	s.ArgoCDTokenSecret = "argocd-token"
	s.ArgoWFServiceName = "argo-server"
	s.ArgoWFServicePort = 2746
	s.BinaryName = binaryName
	s.Codefresh = "codefresh"
	s.CFComponentType = "component"
	s.CFGitSourceType = "git-source"
	s.CFRuntimeDefType = "runtimeDef"
	s.CFRuntimeType = "runtime"
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.CodefreshCM = "codefresh-cm"
	s.CodefreshSA = "codefresh-sa"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
	s.DefaultAPI = "https://g.codefresh.io"
	s.EventBusName = "codefresh-eventbus"
	s.EventReportingEndpoint = "/2.0/api/events"
	s.EventsReporterName = "events-reporter"
	s.GitSourceName = "default-git-source"
	s.IngressName = "-workflows-ingress"
	s.IngressPath = "workflows"
	s.LabelKeyCFType = "codefresh.io/entity"
	s.MaxDefVersion = semver.MustParse(maxDefVersion)
	s.RuntimeDefURL = RuntimeDefURL
	s.RuntimeFilename = "runtime.yaml"
	s.MarketplaceGitSourceName = "marketplace-git-source"
    s.MarketplaceRepo = "https://github.com/codefresh-io/2.0-marketplace.git/"
	s.MarketplacePluginsPath = "plugins"
	s.WaitTimeout = 8 * time.Minute
	s.WorkflowName = "workflow"
	s.WorkflowReporterName = "workflow-reporter"
	initVersion()
}

func initVersion() {
	s.Version.Version = semver.MustParse(version)
	s.Version.BuildDate = buildDate
	s.Version.GitCommit = gitCommit
	s.Version.GoVersion = runtime.Version()
	s.Version.GoCompiler = runtime.Compiler
	s.Version.Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
