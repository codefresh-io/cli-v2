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
)

type Helm struct {
	devel         bool
	chartPathOpts *action.ChartPathOptions
}

func AddFlags(flags *pflag.FlagSet) *Helm {
	helm := &Helm{
		chartPathOpts: &action.ChartPathOptions{},
	}

	flags.BoolVar(&helm.devel, "devel", false, "use development versions, too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored")
	flags.StringVar(&helm.chartPathOpts.Version, "version", "", "specify a version constraint for the chart version to use. This constraint can be a specific tag (e.g. 1.1.1) or it may reference a valid range (e.g. ^2.0.0). If this is not specified, the latest version is used")
	flags.StringVar(&helm.chartPathOpts.RepoURL, "repo", "https://chartmuseum.codefresh.io/gitops-runtime", "chart repository url where to locate the requested chart")

	util.Die(flags.MarkHidden("repo"))

	return helm
}

func (h *Helm) GetValues(valuesFile string) (chartutil.Values, error) {
	if h.chartPathOpts.Version == "" && h.devel {
		h.chartPathOpts.Version = ">0.0.0-0"
	}

	chart, err := h.loadHelmChart()
	if err != nil {
		return nil, err
	}

	values, err := chartutil.ReadValuesFile(valuesFile)
	if err != nil {
		return nil, err
	}

	return chartutil.CoalesceValues(chart, values)
}

func (h *Helm) loadHelmChart() (*chart.Chart, error) {
	cp, err := h.chartPathOpts.LocateChart("gitops-runtime", cli.New())
	if err != nil {
		return nil, err
	}

	return loader.Load(cp)
}

func PathValue[V any](values chartutil.Values, path string) (V, error) {
	var v V

	value, err := values.PathValue(path)
	if err != nil {
		return v, nil
	}

	v, ok := value.(V)
	if !ok {
		return v, fmt.Errorf("\"%s\" must be a %T value", path, v)
	}

	return v, nil
}
