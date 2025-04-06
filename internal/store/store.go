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

package store

import (
	"fmt"
	"runtime"
	"time"

	"github.com/Masterminds/semver/v3"
)

var s Store

var (
	binaryName       = "cli-v2"
	version          = "v99.99.99"
	buildDate        = ""
	gitCommit        = ""
	SegmentWriteKey  = ""
	RuntimeDefURL    = "https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
	OldRuntimeDefURL = "https://github.com/codefresh-io/cli-v2/releases/latest/download/runtime.yaml"
	AddClusterDefURL = "https://github.com/codefresh-io/csdp-official/add-cluster/kustomize"
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
	AddClusterJobName        string
	AppProxyIngressPath      string
	BinaryName               string
	CFInternalGitSources     []string
	CFTokenSecret            string
	CLIDownloadTemplate      string
	CLILatestVersionFileLink string
	DefaultAPI               string
	InClusterName            string
	InClusterServerURL       string
	IngressHost              string
	InsecureIngressHost      bool
	IsDownloadRuntimeLogs    bool
	MarketplaceGitSourceName string //asd
	Silent                   bool
	Version                  Version
	WaitTimeout              time.Duration
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.AddClusterJobName = "csdp-add-cluster-job-"
	s.AppProxyIngressPath = "/app-proxy"
	s.BinaryName = binaryName
	s.CFInternalGitSources = []string{s.MarketplaceGitSourceName}
	s.CFTokenSecret = "codefresh-token"
	s.CLIDownloadTemplate = "https://github.com/codefresh-io/cli-v2/releases/download/%s/cf-%s-%s.tar.gz"
	s.CLILatestVersionFileLink = "https://github.com/codefresh-io/cli-v2/releases/latest/download/version.txt"
	s.DefaultAPI = "https://g.codefresh.io"
	s.InClusterName = "in-cluster"
	s.InClusterServerURL = "https://kubernetes.default.svc"
	s.MarketplaceGitSourceName = "marketplace-git-source"
	s.WaitTimeout = 8 * time.Minute

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
