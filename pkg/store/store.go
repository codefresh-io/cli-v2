package store

import (
	"fmt"
	"runtime"
)

var s Store

var (
	binaryName                = "cli-v2"
	version                   = "v99.99.99"
	buildDate                 = ""
	gitCommit                 = ""
	ArgoCDManifestsURL        = "manifests/argo-cd"
	ArgoEventsManifestsURL    = "manifests/argo-events"
	ArgoRolloutsManifestsURL  = "manifests/argo-rollouts"
	ArgoWorkflowsManifestsURL = "manifests/argo-workflows"
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
	BinaryName                string
	DefaultAPI                string
	Version                   Version
	ArgoCDManifestsURL        string
	ArgoEventsManifestsURL    string
	ArgoRolloutsManifestsURL  string
	ArgoWorkflowsManifestsURL string
	CFTokenSecret             string
	CFTokenSecretKey          string
	CFComponentKey            string
	EventReportingEndpoint    string
	EventBusName              string
	ComponentsReporterName    string
	ComponentsReporterSA      string
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.BinaryName = binaryName
	s.DefaultAPI = "https://g.codefresh.io"
	s.ArgoCDManifestsURL = ArgoCDManifestsURL
	s.ArgoEventsManifestsURL = ArgoEventsManifestsURL
	s.ArgoRolloutsManifestsURL = ArgoRolloutsManifestsURL
	s.ArgoWorkflowsManifestsURL = ArgoWorkflowsManifestsURL
	s.CFTokenSecret = "codefresh-token"
	s.CFTokenSecretKey = "token"
	s.CFComponentKey = "codefresh.io/component"
	s.EventReportingEndpoint = "/argo/api/events"
	s.EventBusName = "codefresh-eventbus"
	s.ComponentsReporterName = "components-reporter"
	s.ComponentsReporterSA = "components-reporter-sa"
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
