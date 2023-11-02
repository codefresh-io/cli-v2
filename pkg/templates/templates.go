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

package templates

import (
	"bytes"
	_ "embed"
	"html/template"

	apapp "github.com/argoproj-labs/argocd-autopilot/pkg/application"
)

type (
	ArgoRolloutsConfig struct {
		AppName       string
		ClusterName   string
		RepoURL       string
		TargetVersion string
	}

	GitSourceConfig struct {
		apapp.Config

		Exclude     string `json:"exclude"`
		Include     string `json:"include"`
		RuntimeName string // not coming from json
	}

	RolloutReporterConfig struct {
		Name          string
		Namespace     string
		ClusterName   string
		EventEndpoint string
	}
)

var (
	//go:embed argo-rollouts.tmpl
	argoRolloutsTmplStr  string
	argoRolloutsTemplate = template.Must(template.New("argo-rollouts").Parse(argoRolloutsTmplStr))

	//go:embed git-source.tmpl
	gitSourceTmplStr  string
	gitSourceTemplate = template.Must(template.New("git-source").Parse(gitSourceTmplStr))

	//go:embed rollout-reporter.tmpl
	rolloutReporterTmplStr  string
	rolloutReporterTemplate = template.Must(template.New("rollout-reporter").Parse(rolloutReporterTmplStr))
)

func RenderArgoRollouts(config *ArgoRolloutsConfig) ([]byte, error) {
	return renderTemplate(argoRolloutsTemplate, config)
}

func RenderGitSource(config *GitSourceConfig) ([]byte, error) {
	return renderTemplate(gitSourceTemplate, config)
}

func RenderRolloutReporter(config *RolloutReporterConfig) ([]byte, error) {
	return renderTemplate(rolloutReporterTemplate, config)
}

func renderTemplate(t *template.Template, data any) ([]byte, error) {
	var b bytes.Buffer
	err := t.Execute(&b, data)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
