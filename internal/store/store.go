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

package store

import (
	"fmt"
	"runtime"
	"time"

	"github.com/Masterminds/semver/v3"
	apaputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
)

var s Store

var (
	binaryName      = "cli-v2"
	version         = "v99.99.99"
	buildDate       = ""
	gitCommit       = ""
	SegmentWriteKey = ""
	// please do not touch this field it is deprecated, it's only here to allow to install runtimes with version < 0.0.569
	maxDefVersion           = "2.1.2"
	RuntimeDefURL           = "https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
	OldRuntimeDefURL        = "https://github.com/codefresh-io/cli-v2/releases/latest/download/runtime.yaml"
	AddClusterDefURL        = "https://github.com/codefresh-io/csdp-official/add-cluster/kustomize"
	lastRuntimeVersionInCLI = "v0.0.569"
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
	AddClusterJobName                 string
	AnnotationKeyReleaseName          string
	AnnotationKeyReleaseNamespace     string
	AppProxyIngressPath               string
	ArgoWfIngressPath                 string
	BinaryName                        string
	CFComponentType                   string
	CFGitSourceType                   string
	CFInternalGitSources              []string
	CFTokenSecret                     string
	CFTokenSecretKey                  string
	CLIDownloadTemplate               string
	CLILatestVersionFileLink          string
	DefaultAPI                        string
	DefaultNamespace                  string
	DocsLink                          string
	EventReportingEndpoint            string
	GitTokensLink                     string
	InClusterName                     string
	InClusterServerURL                string
	IngressHost                       string
	InsecureIngressHost               bool
	InternalRouterIngressName         string
	InternalRouterInternalIngressName string
	InternalRouterServiceName         string
	InternalRouterServicePort         int32
	IsDownloadRuntimeLogs             bool
	KubeVersionConstrint              *semver.Constraints
	LabelFieldCFType                  string
	LabelGitIntegrationTypeKey        string //asd
	LabelGitIntegrationTypeValue      string
	LabelKeyCFType                    string
	LabelSelectorGitIntegrationSecret string
	LabelSelectorSealedSecret         string
	MarketplaceGitSourceName          string //asd
	MinimumCpuRequired                string
	MinimumMemorySizeRequired         string
	NetworkTesterGenerateName         string
	NetworkTesterImage                string
	NetworkTesterName                 string
	OldRuntimeDefURL                  string //asd
	RequirementsLink                  string
	RolloutReporterName               string
	RolloutResourceName               string
	RuntimeDefURL                     string //asd
	SccName                           string
	Silent                            bool
	TCPConnectionTesterGenerateName   string
	TCPConnectionTesterName           string
	Version                           Version
	WaitTimeout                       time.Duration
	WebhooksIngressPath               string
	WorkflowReporterName              string //asd
}

// Get returns the global store
func Get() *Store {
	return &s
}

func (s *Store) IsCustomDefURL(orgRepo string) bool {
	_, runtimeDefOrgRepo, _, _, _, _, _ := apaputil.ParseGitUrl(s.RuntimeDefURL)
	_, oldRuntimeDefOrgRepo, _, _, _, _, _ := apaputil.ParseGitUrl(s.OldRuntimeDefURL)

	return orgRepo != runtimeDefOrgRepo && orgRepo != oldRuntimeDefOrgRepo
}

func init() {
	s.AddClusterJobName = "csdp-add-cluster-job-"
	s.AnnotationKeyReleaseName = "meta.helm.sh/release-name"
	s.AnnotationKeyReleaseNamespace = "meta.helm.sh/release-namespace"
	s.AppProxyIngressPath = "/app-proxy"
	s.ArgoWfIngressPath = "/workflows"
	s.BinaryName = binaryName
	s.CFComponentType = "component"
	s.CFGitSourceType = "git-source"
	s.CFInternalGitSources = []string{s.MarketplaceGitSourceName}
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.CLIDownloadTemplate = "https://github.com/codefresh-io/cli-v2/releases/download/%s/cf-%s-%s.tar.gz"
	s.CLILatestVersionFileLink = "https://github.com/codefresh-io/cli-v2/releases/latest/download/version.txt"
	s.DefaultAPI = "https://g.codefresh.io"
	s.DefaultNamespace = "default"
	s.DocsLink = "https://codefresh.io/csdp-docs/"
	s.EventReportingEndpoint = "/2.0/api/events"
	s.GitTokensLink = "https://codefresh.io/csdp-docs/docs/reference/git-tokens/"
	s.InClusterName = "in-cluster"
	s.InClusterServerURL = "https://kubernetes.default.svc"
	s.InternalRouterIngressName = "-internal-router-ingress"
	s.InternalRouterInternalIngressName = "-internal-router-internal-ingress"
	s.InternalRouterServiceName = "internal-router"
	s.InternalRouterServicePort = 80
	s.KubeVersionConstrint, _ = semver.NewConstraint("1.21-0 - 1.28-0")
	s.LabelFieldCFType = "codefresh_io_entity"
	s.LabelKeyCFType = "codefresh.io/entity"
	s.LabelGitIntegrationTypeKey = "io.codefresh.integration-type"
	s.LabelGitIntegrationTypeValue = "git"
	s.LabelSelectorGitIntegrationSecret = fmt.Sprintf("%s=%s", s.LabelGitIntegrationTypeKey, s.LabelGitIntegrationTypeValue)
	s.LabelSelectorSealedSecret = "codefresh.io/sealing-key=true"
	s.MarketplaceGitSourceName = "marketplace-git-source"
	s.MinimumCpuRequired = "2"
	s.MinimumMemorySizeRequired = "5000"
	s.NetworkTesterGenerateName = "cf-network-tester-"
	s.NetworkTesterImage = "quay.io/codefresh/cf-venona-network-tester:latest"
	s.NetworkTesterName = "cf-network-tester"
	s.OldRuntimeDefURL = OldRuntimeDefURL
	s.RequirementsLink = "https://codefresh.io/csdp-docs/docs/runtime/requirements/"
	s.RolloutReporterName = "rollout-reporter"
	s.RolloutResourceName = "rollouts"
	s.RuntimeDefURL = RuntimeDefURL
	s.SccName = "cf-scc"
	s.TCPConnectionTesterGenerateName = "cf-tcp-connections-tester-"
	s.TCPConnectionTesterName = "cf-tcp-connections-tester"
	s.WaitTimeout = 8 * time.Minute
	s.WebhooksIngressPath = "/webhooks"
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
