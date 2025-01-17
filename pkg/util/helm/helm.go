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

package helm

import (
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/registry"
)

//go:generate mockgen -destination=./mocks/helm.go -package=helm -source=./helm.go Helm

type (
	Helm interface {
		GetValues(valuesFile string, loadFromChart bool) (chartutil.Values, error)
		GetDependency(name string) (string, string, error)
	}

	helmImpl struct {
		chart   string
		devel   bool
		install *action.Install
	}
)

func AddFlags(flags *pflag.FlagSet) (Helm, error) {
	client, err := registry.NewClient()
	if err != nil {
		return nil, err
	}

	helm := &helmImpl{
		install: action.NewInstall(&action.Configuration{
			RegistryClient: client,
		}),
	}

	flags.BoolVar(&helm.devel, "devel", false, "use development versions, too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored")
	flags.StringVar(&helm.install.ChartPathOptions.Version, "version", "", "specify a version constraint for the chart version to use. This constraint can be a specific tag (e.g. 1.1.1) or it may reference a valid range (e.g. ^2.0.0). If this is not specified, the latest version is used")
	flags.StringVar(&helm.chart, "chart", "oci://quay.io/codefresh/gitops-runtime", "chart oci url [oci://quay.io/codefresh/gitops-runtime]")

	util.Die(flags.MarkHidden("chart"))

	return helm, nil
}

func (h *helmImpl) GetValues(valuesFile string, loadFromChart bool) (chartutil.Values, error) {
	values, err := chartutil.ReadValuesFile(valuesFile)
	if err != nil {
		return nil, err
	}

	if !loadFromChart {
		return values, nil
	}

	chart, err := h.loadHelmChart()
	if err != nil {
		return nil, err
	}

	return chartutil.CoalesceValues(chart, values)
}

func (h *helmImpl) GetDependency(name string) (string, string, error) {
	chart, err := h.loadHelmChart()
	if err != nil {
		return "", "", err
	}

	for _, dep := range chart.Metadata.Dependencies {
		if dep.Name == name {
			return dep.Repository, dep.Version, nil
		}
	}

	return "", "", fmt.Errorf("dependency %q not found", name)
}

func (h *helmImpl) loadHelmChart() (*chart.Chart, error) {
	if h.install.ChartPathOptions.Version == "" && h.devel {
		h.install.ChartPathOptions.Version = ">0.0.0-0"
	}

	settings := cli.New()
	cp, err := h.install.LocateChart(h.chart, settings)
	if err != nil {
		return nil, err
	}

	return loader.Load(cp)
}

func PathValue[V any](values chartutil.Values, path string) (V, error) {
	var v V

	value, err := values.PathValue(path)
	if err != nil {
		return v, err
	}

	v, ok := value.(V)
	if !ok {
		return v, fmt.Errorf("\"%s\" must be a %T value", path, v)
	}

	return v, nil
}
