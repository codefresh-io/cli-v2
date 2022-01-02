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

// Copyright 2021 The Codefresh Authors.
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

package runtime

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"

	"github.com/Masterminds/semver/v3"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/application"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	"github.com/ghodss/yaml"
	billyUtils "github.com/go-git/go-billy/v5/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	Runtime struct {
		metav1.TypeMeta   `json:",inline"`
		metav1.ObjectMeta `json:"metadata"`

		Spec RuntimeSpec `json:"spec"`
	}

	RuntimeSpec struct {
		DefVersion         *semver.Version `json:"defVersion"`
		Version            *semver.Version `json:"version"`
		BootstrapSpecifier string          `json:"bootstrapSpecifier"`
		Components         []AppDef        `json:"components"`
		Cluster            string          `json:"cluster"`
		IngressHost        string          `json:"ingressHost"`
		Repo               string          `json:"repo"`

		devMode bool
	}

	CommonConfig struct {
		CodefreshBaseURL string `json:"baseUrl"`
	}

	AppDef struct {
		Name string `json:"name"`
		Type string `json:"type"`
		URL  string `json:"url"`
		Wait bool   `json:"wait"`
	}
)

func Download(version *semver.Version, name string) (*Runtime, error) {
	var (
		body []byte
		err  error
	)

	devMode := false
	if strings.HasPrefix(store.RuntimeDefURL, "http") {
		urlString := store.RuntimeDefURL
		if version != nil {
			urlString = strings.Replace(urlString, "/releases/latest/download", "/releases/download/v"+version.String(), 1)
		}

		res, err := http.Get(urlString)
		if err != nil {
			return nil, fmt.Errorf("failed to download runtime definition: %w", err)
		}

		defer res.Body.Close()
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read runtime definition data: %w", err)
		}
	} else {
		body, err = ioutil.ReadFile(store.RuntimeDefURL)
		if err != nil {
			return nil, fmt.Errorf("failed to read runtime definition data: %w", err)
		}

		devMode = true
	}

	runtime := &Runtime{}
	err = yaml.Unmarshal(body, runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime definition data: %w", err)
	}

	runtime.Name = name
	runtime.Namespace = name
	runtime.Spec.devMode = devMode
	for i := range runtime.Spec.Components {
		runtime.Spec.Components[i].URL = runtime.Spec.fullURL(runtime.Spec.Components[i].URL)
	}

	return runtime, nil
}

func Load(fs fs.FS, filename string) (*Runtime, error) {
	cm := &v1.ConfigMap{}
	if err := fs.ReadYamls(filename, cm); err != nil {
		return nil, fmt.Errorf("failed to load runtime from '%s': %w", filename, err)
	}

	data := cm.Data["runtime"]
	runtime := &Runtime{}
	if err := yaml.Unmarshal([]byte(data), runtime); err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime from '%s': %w", filename, err)
	}

	for i := range runtime.Spec.Components {
		runtime.Spec.Components[i].URL = runtime.Spec.fullURL(runtime.Spec.Components[i].URL)
	}

	return runtime, nil
}

func (r *Runtime) Save(fs fs.FS, filename string, config *CommonConfig) error {
	runtimeData, err := yaml.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal runtime: %w", err)
	}

	cm := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      store.Get().CodefreshCM,
			Namespace: r.Namespace,
			Labels: map[string]string{
				apstore.Default.LabelKeyAppManagedBy: store.Get().Codefresh,
				store.Get().LabelKeyCFType:           store.Get().CFRuntimeDefType,
			},
		},
		Data: map[string]string{
			"runtime":  string(runtimeData),
			"base-url": config.CodefreshBaseURL,
		},
	}

	return fs.WriteYamls(filename, cm)
}

func (r *Runtime) Upgrade(fs fs.FS, newRt *Runtime, config *CommonConfig) ([]AppDef, error) {
	newComponents, err := r.Spec.upgrade(fs, &newRt.Spec)
	if err != nil {
		return nil, err
	}

	if err := newRt.Save(fs, fs.Join(apstore.Default.BootsrtrapDir, r.Name+".yaml"), config); err != nil {
		return nil, fmt.Errorf("failed to save runtime definition: %w", err)
	}

	return newComponents, nil
}

func (r *RuntimeSpec) upgrade(fs fs.FS, newRt *RuntimeSpec) ([]AppDef, error) {
	log.G().Infof("Upgrading bootstrap specifier")
	argocdDir := fs.Join(apstore.Default.BootsrtrapDir, apstore.Default.ArgoCDName)
	if err := updateKustomization(fs, argocdDir, r.FullSpecifier(), newRt.FullSpecifier()); err != nil {
		return nil, fmt.Errorf("failed to upgrade bootstrap specifier: %w", err)
	}

	newRt.Cluster = r.Cluster
	newRt.IngressHost = r.IngressHost
	newRt.Repo = r.Repo

	newComponents := make([]AppDef, 0)
	for _, newComponent := range newRt.Components {
		curComponent := r.component(newComponent.Name)
		if curComponent != nil {
			log.G().Infof("Upgrading '%s'", newComponent.Name)
			baseDir := fs.Join(apstore.Default.AppsDir, curComponent.Name, apstore.Default.BaseDir)
			if err := updateKustomization(fs, baseDir, curComponent.URL, newComponent.URL); err != nil {
				return nil, fmt.Errorf("failed to upgrade app '%s': %w", curComponent.Name, err)
			}
		} else {
			log.G().Debugf("marking '%s' to be created later", newComponent.Name)
			newComponents = append(newComponents, newComponent)
		}
	}

	for _, curComponent := range r.Components {
		newComponent := newRt.component(curComponent.Name)
		if newComponent == nil {
			log.G().Infof("Deleting '%s'", curComponent.Name)
			if err := curComponent.delete(fs); err != nil {
				return nil, fmt.Errorf("failed to delete app '%s': %w", curComponent.Name, err)
			}
		}
	}

	return newComponents, nil
}

func (a *RuntimeSpec) component(name string) *AppDef {
	for _, c := range a.Components {
		if c.Name == name {
			return &c
		}
	}

	return nil
}

func (r *RuntimeSpec) FullSpecifier() string {
	return buildFullURL(r.BootstrapSpecifier, r.Version, r.devMode)
}

func (r *RuntimeSpec) fullURL(url string) string {
	return buildFullURL(url, r.Version, r.devMode)
}

func (a *AppDef) CreateApp(ctx context.Context, f kube.Factory, cloneOpts *git.CloneOptions, projectName, cfType, include, exclude string) error {
	timeout := time.Duration(0)
	if a.Wait {
		timeout = store.Get().WaitTimeout
	}

	return apcmd.RunAppCreate(ctx, &apcmd.AppCreateOptions{
		CloneOpts:     cloneOpts,
		AppsCloneOpts: &git.CloneOptions{},
		ProjectName:   projectName,
		AppOpts: &application.CreateOptions{
			AppName:       a.Name,
			AppSpecifier:  a.URL,
			AppType:       a.Type,
			DestNamespace: projectName,
			Labels: map[string]string{
				util.EscapeAppsetFieldName(store.Get().LabelKeyCFType): cfType,
			},
			Exclude: exclude,
			Include: include,
		},
		KubeFactory: f,
		Timeout:     timeout,
	})
}

func (a *AppDef) delete(fs fs.FS) error {
	return billyUtils.RemoveAll(fs, fs.Join(apstore.Default.AppsDir, a.Name))
}

func updateKustomization(fs fs.FS, directory, fromURL, toURL string) error {
	kust, err := kustutil.ReadKustomization(fs, directory)
	if err != nil {
		return err
	}

	if err = kustutil.ReplaceResource(kust, fromURL, toURL); err != nil {
		return err
	}

	return kustutil.WriteKustomization(fs, kust, directory)
}

func buildFullURL(urlString string, version *semver.Version, devMode bool) string {
	if devMode || version == nil {
		return urlString
	}

	urlObj, _ := url.Parse(urlString)
	v := urlObj.Query()
	if v.Get("ref") == "" {
		v.Add("ref", "v"+version.String())
		urlObj.RawQuery = v.Encode()
	}

	return urlObj.String()
}
