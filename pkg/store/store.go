// Copyright 2023 The Codefresh Authors.
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
	AnalysisRunResourceName           string
	AnnotationKeySyncWave             string
	AppProxyIngressName               string
	AppProxyIngressPath               string
	AppProxyServiceName               string
	ArgoCD                            string
	ArgoCDServerName                  string
	ArgoCDTokenKey                    string
	ArgoCDTokenSecret                 string
	ArgoWfIngressPath                 string
	ArgoWfServiceName                 string
	BinaryName                        string
	CFComponentType                   string
	CFGitSourceType                   string
	CFInternalGitSources              []string
	CFInternalReporters               []string
	CFRuntimeDefType                  string
	CFRuntimeType                     string
	CFStoreIVSecretKey                string
	CFTokenSecret                     string
	CFTokenSecretKey                  string
	CLIDownloadTemplate               string
	CLILatestVersionFileLink          string
	ClusterResourcesPath              string
	Codefresh                         string
	CodefreshCM                       string
	CodefreshSA                       string
	ComponentsReporterName            string
	ComponentsReporterSA              string
	ComponentsReporterURL             string
	DefaultAPI                        string
	DefaultNamespace                  string
	DefVersionToLastCLIVersion        map[string]string
	DemoCalendarDependencyName        string
	DemoCalendarEventName             string
	DemoCalendarEventSourceFileName   string
	DemoCalendarEventSourceObjectName string
	DemoCalendarSensorFileName        string
	DemoCalendarSensorObjectName      string
	DemoGitDependencyName             string
	DemoGitEventName                  string
	DemoGitEventSourceFileName        string
	DemoGitEventSourceObjectName      string
	DemoGitEventSourceServicePort     int32
	DemoGitEventSourceTargetPort      string
	DemoGitSensorFileName             string
	DemoGitSensorObjectName           string
	DemoGitTriggerTemplateName        string
	DemoWorkflowTemplateFileName      string
	DemoWorkflowTemplateName          string
	DocsLink                          string
	DownloadCliLink                   string
	EventBusName                      string
	EventReportingEndpoint            string
	EventsReporterName                string
	GithubEventTypeHeader             string
	GitlabEventTypeHeader             string
	GitSourceName                     string
	GitTokenSecretKey                 string
	GitTokenSecretObjectName          string
	GitTokensLink                     string
	GsCreateFlow                      string
	InClusterName                     string
	InClusterServerURL                string
	InClusterPath                     string
	IngressHost                       string
	InsecureIngressHost               bool
	InternalRouterIngressFilePath     string
	InternalRouterIngressName         string
	InternalRouterInternalIngressName string
	InternalRouterServiceName         string
	InternalRouterServicePort         int32
	IscRuntimesDir                    string
	IsDownloadRuntimeLogs             bool
	KubeVersionConstrint              *semver.Constraints
	LabelFieldCFType                  string
	LabelKeyCFInternal                string
	LabelKeyCFType                    string
	LabelSelectorGitIntegrationSecret string
	LabelSelectorSealedSecret         string
	LastRuntimeVersionInCLI           *semver.Version
	MarketplaceGitSourceName          string
	MarketplaceRepo                   string
	MasterIngressName                 string
	MaxDefVersion                     *semver.Version
	MinimumCpuRequired                string
	MinimumLocalDiskSizeRequired      string
	MinimumMemorySizeRequired         string
	NetworkTesterGenerateName         string
	NetworkTesterImage                string
	NetworkTesterName                 string
	OldRuntimeDefURL                  string
	ReplicaSetResourceName            string
	RequirementsLink                  string
	RolloutReporterName               string
	RolloutReporterServiceAccount     string
	RolloutResourceName               string
	RuntimeDefURL                     string
	SccName                           string
	SetDefaultResources               bool
	Silent                            bool
	TCPConnectionTesterGenerateName   string
	TCPConnectionTesterName           string
	Version                           Version
	WaitTimeout                       time.Duration
	WebhooksIngressPath               string
	WebhooksRootPath                  string
	WorkflowName                      string
	WorkflowReporterName              string
	WorkflowResourceName              string
	WorkflowTriggerServiceAccount     string
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
	s.AnalysisRunResourceName = "analysisruns"
	s.AnnotationKeySyncWave = "argocd.argoproj.io/sync-wave"
	s.AppProxyIngressName = "-cap-app-proxy"
	s.AppProxyIngressPath = "/app-proxy"
	s.AppProxyServiceName = "cap-app-proxy"
	s.ArgoCD = "argo-cd"
	s.ArgoCDServerName = "argocd-server"
	s.ArgoCDTokenKey = "token"
	s.ArgoCDTokenSecret = "argocd-token"
	s.ArgoWfIngressPath = "/workflows"
	s.ArgoWfServiceName = "argo-server"
	s.BinaryName = binaryName
	s.CFComponentType = "component"
	s.CFGitSourceType = "git-source"
	s.CFInternalGitSources = []string{s.MarketplaceGitSourceName}
	s.CFInternalReporters = []string{s.EventsReporterName, s.WorkflowReporterName, s.RolloutReporterName}
	s.CFRuntimeDefType = "runtimeDef"
	s.CFRuntimeType = "runtime"
	s.CFStoreIVSecretKey = "encryptionIV"
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.CLIDownloadTemplate = "https://github.com/codefresh-io/cli-v2/releases/download/%s/cf-%s-%s.tar.gz"
	s.CLILatestVersionFileLink = "https://github.com/codefresh-io/cli-v2/releases/latest/download/version.txt"
	s.ClusterResourcesPath = "/bootstrap/cluster-resources.yaml"
	s.Codefresh = "codefresh"
	s.CodefreshCM = "codefresh-cm"
	s.CodefreshSA = "codefresh-sa"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
	s.DefaultAPI = "https://g.codefresh.io"
	s.DefaultNamespace = "default"
	s.DemoCalendarDependencyName = "calendar-dep"
	s.DemoCalendarEventName = "example-with-interval"
	s.DemoCalendarEventSourceFileName = "calendar.event-source.yaml"
	s.DemoCalendarEventSourceObjectName = "calendar"
	s.DemoCalendarSensorFileName = "calendar.sensor.yaml"
	s.DemoCalendarSensorObjectName = "calendar"
	s.DemoGitDependencyName = "push-commit"
	s.DemoGitEventName = "push-commit"
	s.DemoGitEventSourceFileName = "push-commit.event-source.yaml"
	s.DemoGitEventSourceObjectName = "push-commit"
	s.DemoGitEventSourceServicePort = 80
	s.DemoGitEventSourceTargetPort = "80"
	s.DemoGitSensorFileName = "push-commit.sensor.yaml"
	s.DemoGitSensorObjectName = "push-commit"
	s.DemoGitTriggerTemplateName = "push-commit"
	s.DemoWorkflowTemplateFileName = "echo-message.workflow-template.yaml"
	s.DemoWorkflowTemplateName = "echo-message"
	s.DocsLink = "https://codefresh.io/csdp-docs/"
	s.DownloadCliLink = "https://codefresh.io/csdp-docs/docs/clients/csdp-cli/"
	s.EventBusName = "codefresh-eventbus"
	s.EventReportingEndpoint = "/2.0/api/events"
	s.EventsReporterName = "events-reporter"
	s.GithubEventTypeHeader = "X-GitHub-Event"
	s.GitlabEventTypeHeader = "X-Gitlab-Event"
	s.GitSourceName = "default-git-source"
	s.GitTokenSecretKey = "git_token"
	s.GitTokenSecretObjectName = "autopilot-secret"
	s.GitTokensLink = "https://codefresh.io/csdp-docs/docs/reference/git-tokens/"
	s.InClusterName = "in-cluster"
	s.InClusterServerURL = "https://kubernetes.default.svc"
	s.InClusterPath = "/bootstrap/cluster-resources/in-cluster"
	s.InternalRouterIngressFilePath = "internal-router"
	s.InternalRouterIngressName = "-internal-router-ingress"
	s.InternalRouterInternalIngressName = "-internal-router-internal-ingress"
	s.InternalRouterServiceName = "internal-router"
	s.InternalRouterServicePort = 80
	s.IscRuntimesDir = "runtimes"
	s.KubeVersionConstrint, _ = semver.NewConstraint("1.21-0 - 1.26-0")
	s.LabelFieldCFType = "codefresh_io_entity"
	s.LabelKeyCFInternal = "codefresh.io/internal"
	s.LabelKeyCFType = "codefresh.io/entity"
	s.LabelSelectorGitIntegrationSecret = "io.codefresh.integration-type=git"
	s.LabelSelectorSealedSecret = "codefresh.io/sealing-key=true"
	s.LastRuntimeVersionInCLI = semver.MustParse(lastRuntimeVersionInCLI)
	s.MarketplaceGitSourceName = "marketplace-git-source"
	s.MarketplaceRepo = "https://github.com/codefresh-io/argo-hub.git"
	s.MasterIngressName = "-master"
	s.MaxDefVersion = semver.MustParse(maxDefVersion)
	s.MinimumCpuRequired = "2"
	s.MinimumMemorySizeRequired = "5000"
	s.NetworkTesterGenerateName = "cf-network-tester-"
	s.NetworkTesterImage = "quay.io/codefresh/cf-venona-network-tester:latest"
	s.NetworkTesterName = "cf-network-tester"
	s.OldRuntimeDefURL = OldRuntimeDefURL
	s.ReplicaSetResourceName = "replicasets"
	s.RequirementsLink = "https://codefresh.io/csdp-docs/docs/runtime/requirements/"
	s.RolloutReporterName = "rollout-reporter"
	s.RolloutReporterServiceAccount = "rollout-reporter-sa"
	s.RolloutResourceName = "rollouts"
	s.RuntimeDefURL = RuntimeDefURL
	s.SccName = "cf-scc"
	s.TCPConnectionTesterGenerateName = "cf-tcp-connections-tester-"
	s.TCPConnectionTesterName = "cf-tcp-connections-tester"
	s.WaitTimeout = 8 * time.Minute
	s.WebhooksIngressPath = "/webhooks"
	s.WebhooksRootPath = "/webhooks"
	s.WorkflowName = "workflow"
	s.WorkflowReporterName = "workflow-reporter"
	s.WorkflowResourceName = "workflows"
	s.WorkflowTriggerServiceAccount = "argo"
	s.DefVersionToLastCLIVersion = map[string]string{
		"1.0.0": "0.0.237",
		"1.0.1": "0.0.510",
		"2.0.0": "0.0.541",
		"2.1.0": "0.0.548",
		"2.1.1": "0.0.569",
	}

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
