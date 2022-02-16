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

package store

import (
	"fmt"
	"runtime"
	"time"

	"github.com/Masterminds/semver/v3"
)

var s Store

var (
	binaryName      = "cli-v2"
	version         = "v99.99.99"
	buildDate       = ""
	gitCommit       = ""
	segmentWriteKey = ""
	maxDefVersion   = "1.0.0"
	RuntimeDefURL   = "manifests/runtime.yaml"
	ArgoAgentURL    = "manifests/argo-agent/agent.yaml"
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
	ArgoCDServerName                     string
	ArgoCDTokenKey                       string
	ArgoCDTokenSecret                    string
	ArgoCDAgentCFTokenKey                string
	ArgoCDAgentCFTokenSecret             string
	ArgoCDAgentSA                        string
	ArgoWFServiceName                    string
	ArgoWFServicePort                    int32
	BinaryName                           string
	Codefresh                            string
	CodefreshDeliveryPipelines           string
	CFComponentType                      string
	CFGitSourceType                      string
	CFRuntimeDefType                     string
	CFRuntimeType                        string
	CFTokenSecret                        string
	CFTokenSecretKey                     string
	CFStoreIVSecretKey                   string
	CodefreshCM                          string
	CodefreshSA                          string
	ComponentsReporterName               string
	ComponentsReporterSA                 string
	ComponentsReporterURL                string
	DefaultAPI                           string
	EventBusName                         string
	EventReportingEndpoint               string
	EventsReporterName                   string
	ArgoCDAgentReporterName              string
	GitSourceName                        string
	WorkflowsIngressName                 string
	WorkflowsIngressPath                 string
	AppProxyIngressName                  string
	AppProxyIngressPath                  string
	AppProxyServicePort                  int32
	AppProxyServiceName                  string
	DocsLink                             string
	LabelKeyCFType                       string
	MarketplaceGitSourceName             string
	MarketplaceRepo                      string
	MaxDefVersion                        *semver.Version
	RuntimeDefURL                        string
	Version                              Version
	WaitTimeout                          time.Duration
	WorkflowName                         string
	WorkflowReporterName                 string
	WorkflowTriggerServiceAccount        string
	CronExampleSensorFileName            string
	CronExampleEventSourceFileName       string
	CronExampleWfTemplateFileName        string
	CronExampleEventSourceName           string
	CronExampleEventName                 string
	CronExampleTriggerTemplateName       string
	CronExampleDependencyName            string
	GithubExampleEventSourceFileName     string
	GithubExampleEventSourceObjectName   string
	GithubExampleEventSourceEndpointPath string
	GithubExampleEventSourceTargetPort   string
	GithubExampleEventSourceServicePort  int32
	GithubExampleIngressFileName         string
	GithubExampleIngressObjectName       string
	GithubExampleSensorFileName          string
	GithubExampleSensorObjectName        string
	GithubExampleWfTemplateFileName      string
	GithubExampleEventName               string
	GithubExampleTriggerTemplateName     string
	GithubExampleDependencyName          string
	GithubAccessTokenSecretObjectName    string
	GithubAccessTokenSecretKey           string
	ArgoCD                               string
	Silent                               bool
	InsecureIngressHost                  bool
	BypassIngressClassCheck              bool
	SkipIngress                          bool
	MinimumMemorySizeRequired            string
	MinimumCpuRequired                   string
	MinimumLocalDiskSizeRequired         string
	ReplicaSetReporterName               string
	ReplicaSetReporterServiceAccount     string
	ReplicaSetResourceName               string
	WorkflowResourceName                 string
	RequirementsLink                     string
	DownloadCliLink                      string
	RolloutReporterName                  string
	RolloutResourceName                  string
	RolloutReporterServiceAccount        string
	SegmentWriteKey                      string
	DefaultNamespace                     string
	NetworkTesterName                    string
	NetworkTesterGenerateName            string
	NetworkTesterImage                   string
	MinKubeVersion                       string
	MaxKubeVersion                       string
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
	s.CodefreshDeliveryPipelines = "codefresh-delivery-pipelines"
	s.CFComponentType = "component"
	s.CFGitSourceType = "git-source"
	s.CFRuntimeDefType = "runtimeDef"
	s.CFRuntimeType = "runtime"
	s.CFTokenSecret = "codefresh-token"
	s.ArgoCDAgentCFTokenKey = "token"
	s.ArgoCDAgentCFTokenSecret = "cf-argocd-agent"
	s.ArgoCDAgentReporterName = "argocd-agent"
	s.ArgoCDAgentSA = "argocd-agent"
	s.CFTokenSecretKey = "token"
	s.CFStoreIVSecretKey = "encryptionIV"
	s.CodefreshCM = "codefresh-cm"
	s.CodefreshSA = "codefresh-sa"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
	s.DefaultAPI = "https://g.codefresh.io"
	s.EventBusName = "codefresh-eventbus"
	s.EventReportingEndpoint = "/2.0/api/events"
	s.EventsReporterName = "events-reporter"
	s.GitSourceName = "default-git-source"
	s.WorkflowsIngressName = "-workflows-ingress"
	s.WorkflowsIngressPath = "workflows"
	s.AppProxyIngressName = "-cap-app-proxy"
	s.AppProxyIngressPath = "app-proxy"
	s.AppProxyServicePort = 3017
	s.AppProxyServiceName = "cap-app-proxy"
	s.DocsLink = "https://codefresh.io/csdp-docs/"
	s.LabelKeyCFType = "codefresh.io/entity"
	s.MaxDefVersion = semver.MustParse(maxDefVersion)
	s.RuntimeDefURL = RuntimeDefURL
	s.MarketplaceGitSourceName = "marketplace-git-source"
	s.MarketplaceRepo = "https://github.com/codefresh-io/argo-hub.git"
	s.WaitTimeout = 8 * time.Minute
	s.WorkflowName = "workflow"
	s.WorkflowReporterName = "workflow-reporter"
	s.WorkflowTriggerServiceAccount = "argo"
	s.CronExampleEventSourceFileName = "event-source.calendar.yaml"
	s.CronExampleSensorFileName = "sensor.cron.yaml"
	s.CronExampleWfTemplateFileName = "workflow-template.hello-world.yaml"
	s.CronExampleEventSourceName = "calendar"
	s.CronExampleEventName = "example-with-interval"
	s.CronExampleTriggerTemplateName = "hello-world"
	s.CronExampleDependencyName = "calendar-dep"
	s.GithubExampleEventSourceFileName = "push-github.event-source.yaml"
	s.GithubExampleEventSourceObjectName = "push-github"
	s.GithubExampleEventSourceEndpointPath = "/webhooks/push-github/"
	s.GithubExampleEventSourceTargetPort = "13000"
	s.GithubExampleEventSourceServicePort = 13000
	s.GithubExampleIngressFileName = fmt.Sprintf("%s.ingress.yaml", s.CodefreshDeliveryPipelines)
	s.GithubExampleIngressObjectName = "github"
	s.GithubExampleSensorFileName = "push-github.sensor.yaml"
	s.GithubExampleSensorObjectName = "push-github"
	s.GithubExampleWfTemplateFileName = "workflow-template.hello-world.yaml"
	s.GithubExampleEventName = "push"
	s.GithubExampleTriggerTemplateName = "hello-world"
	s.GithubExampleDependencyName = "github-dep"
	s.GithubAccessTokenSecretObjectName = "autopilot-secret"
	s.GithubAccessTokenSecretKey = "git_token"
	s.ArgoCD = "argo-cd"
	s.MinimumMemorySizeRequired = "5000"
	s.MinimumCpuRequired = "2"
	s.ReplicaSetReporterName = "replicaset-reporter"
	s.ReplicaSetReporterServiceAccount = "replicaset-reporter-sa"
	s.ReplicaSetResourceName = "replicasets"
	s.WorkflowResourceName = "workflows"
	s.RolloutReporterName = "rollout-reporter"
	s.RolloutResourceName = "rollouts"
	s.RolloutReporterServiceAccount = "rollout-reporter-sa"
	s.SegmentWriteKey = segmentWriteKey
	s.RequirementsLink = "https://codefresh.io/csdp-docs/docs/runtime/requirements/"
	s.DownloadCliLink = "https://codefresh.io/csdp-docs/docs/clients/csdp-cli/"
	s.DefaultNamespace = "default"
	s.NetworkTesterName = "cf-network-tester"
	s.NetworkTesterGenerateName = "cf-network-tester-"
	s.NetworkTesterImage = "quay.io/codefresh/cf-venona-network-tester:latest"
	s.MinKubeVersion = "v1.18.0"
	s.MaxKubeVersion = "v1.21.9"

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
