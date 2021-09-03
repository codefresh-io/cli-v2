package util

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"text/template"
)

type (
	CreateAgentOptions struct {
		Name      string
		Namespace string
		CFHost    string
	}
)

func buildMap(options *CreateAgentOptions) map[string]interface{} {
	opts := make(map[string]interface{})
	opts["namespace"] = options.Namespace
	opts["name"] = options.Name
	opts["cfhost"] = options.CFHost
	return opts
}

func CreateAgentResource(options *CreateAgentOptions) ([]byte, error) {
	path, err := filepath.Abs("./manifests/argo-agent/agent.yaml")
	if err != nil {
		return nil, err
	}
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tmpl, err := renderTemplate(string(yamlFile), buildMap(options))
	if err != nil {
		return nil, err
	}
	return []byte(tmpl), err
}

func renderTemplate(dashboardYaml string, values map[string]interface{}) (string, error) {
	tmpl := template.New("dashboard")
	tmpl.Delims("[[", "]]")
	out := new(bytes.Buffer)
	tmpl, err := tmpl.Parse(dashboardYaml)
	if err != nil {
		return "", err
	}
	if err = tmpl.Execute(out, values); err != nil {
		return "", err
	}
	return out.String(), nil
}
