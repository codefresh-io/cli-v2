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
	BinaryName             string
	CFComponentType        string
	CFRuntimeType          string
	CFTokenSecret          string
	CFTokenSecretKey       string
	ComponentsReporterName string
	ComponentsReporterSA   string
	ComponentsReporterURL  string
	DefaultAPI             string
	EventBusName           string
	EventReportingEndpoint string
	GitSourceName          string
	LabelKeyCFType         string
	MaxDefVersion          *semver.Version
	RuntimeDefURL          string
	RuntimeFilename        string
	Version                Version
	WaitTimeout            time.Duration
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.BinaryName = binaryName
	s.CFComponentType = "component"
	s.CFRuntimeType = "runtime"
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
	s.DefaultAPI = "https://g.codefresh.io"
	s.EventBusName = "codefresh-eventbus"
	s.EventReportingEndpoint = "/argo/api/events"
	s.GitSourceName = "default-git-source"
	s.LabelKeyCFType = "codefresh.io/type"
	s.MaxDefVersion = semver.MustParse(maxDefVersion)
	s.RuntimeDefURL = RuntimeDefURL
	s.RuntimeFilename = "runtime.yaml"
	s.WaitTimeout = 5 * time.Minute
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
