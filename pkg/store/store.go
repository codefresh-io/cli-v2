package store

import (
	"fmt"
	"path/filepath"
	"runtime"
)

var s Store

var (
	binaryName               = "cli-v2"
	version                  = "v99.99.99"
	buildDate                = ""
	gitCommit                = ""
	installationManifestsURL = "manifests"
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
	BinaryName string
	Version    Version
	DefaultAPI string

	ArgoCDManifestsURL        string
	ArgoEventsManifestsURL    string
	ArgoRolloutsManifestsURL  string
	ArgoWorkflowsManifestsURL string
}

// Get returns the global store
func Get() *Store {
	return &s
}

func init() {
	s.BinaryName = binaryName
	s.DefaultAPI = "https://g.codefresh.io"
	s.ArgoCDManifestsURL = filepath.Join(installationManifestsURL, "argo-cd")
	s.ArgoEventsManifestsURL = filepath.Join(installationManifestsURL, "argo-events")
	s.ArgoRolloutsManifestsURL = filepath.Join(installationManifestsURL, "argo-rollouts")
	s.ArgoWorkflowsManifestsURL = filepath.Join(installationManifestsURL, "argo-workflows")

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
