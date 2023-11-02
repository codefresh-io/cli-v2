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

package isc

import (
	"fmt"
	"strings"

	apfs "github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
)

type (
	ClusterConfigApp interface {
		AddInclude(path string)
		Server() string
		Write() error
	}

	clusterConfigApp struct {
		fs          apfs.FS
		runtimeName string
		app         *argocdv1alpha1.Application
	}
)

func ReadClusterConfigApp(fs apfs.FS, runtimeName, clusterName string) (ClusterConfigApp, error) {
	app := &argocdv1alpha1.Application{}
	filename := fs.Join("runtimes", runtimeName, clusterName+".yaml")
	err := fs.ReadYamls(filename, app)
	if err != nil {
		return nil, err
	}

	return &clusterConfigApp{
		fs:          fs,
		runtimeName: runtimeName,
		app:         app,
	}, nil
}

func (c *clusterConfigApp) AddInclude(path string) {
	includeStr := c.app.Spec.Source.Directory.Include
	includeArr := strings.Split(includeStr[1:len(includeStr)-1], ",")
	includeArr = append(includeArr, path)
	c.app.Spec.Source.Directory.Include = fmt.Sprintf("{%s}", strings.Join(includeArr, ","))
}

func (c *clusterConfigApp) Server() string {
	return c.app.Spec.Destination.Server
}

func (c *clusterConfigApp) Write() error {
	filename := c.fs.Join("runtimes", c.runtimeName, c.app.Name+".yaml")
	return c.fs.WriteYamls(filename, c.app)
}
