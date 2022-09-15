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

package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/cli-v2/pkg/util/aputil"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"

	"github.com/Masterminds/semver/v3"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	apapp "github.com/argoproj-labs/argocd-autopilot/pkg/application"
	apfs "github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	apaputil "github.com/argoproj-labs/argocd-autopilot/pkg/util"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5/memfs"
	billyUtils "github.com/go-git/go-billy/v5/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	InstallFeature string

	HelmValuesProvider interface {
		GetValues(name string) (string, error)
	}

	Runtime struct {
		metav1.TypeMeta   `json:",inline"`
		metav1.ObjectMeta `json:"metadata"`

		Spec RuntimeSpec `json:"spec"`
	}

	RuntimeSpec struct {
		DefVersion          *semver.Version      `json:"defVersion"`
		Version             *semver.Version      `json:"version"`
		BootstrapSpecifier  string               `json:"bootstrapSpecifier"`
		Components          []AppDef             `json:"components"`
		Cluster             string               `json:"cluster"`
		IngressHost         string               `json:"ingressHost,omitempty"`
		IngressClass        string               `json:"ingressClassName,omitempty"`
		InternalIngressHost string               `json:"internalIngressHost,omitempty"`
		IngressController   string               `json:"ingressController,omitempty"`
		AccessMode          platmodel.AccessMode `json:"accessMode"`
		Repo                string               `json:"repo"`

		devMode bool
	}

	CommonConfig struct {
		CodefreshBaseURL string `json:"baseUrl"`
	}

	AppDef struct {
		Name       string         `json:"name"`
		Type       string         `json:"type"`
		URL        string         `json:"url"`
		SyncWave   int            `json:"syncWave,omitempty"`
		Wait       bool           `json:"wait,omitempty"`
		IsInternal bool           `json:"isInternal,omitempty"`
		Feature    InstallFeature `json:"feature,omitempty"`
		Chart      string         `json:"chart,omitempty"`
		Include    string         `json:"include,omitempty"`
		Exclude    string         `json:"exclude,omitempty"`
	}

	HelmConfig struct {
		apapp.Config
		SrcChart string `json:"srcChart"`
		Values   string `json:"values,omitempty"`
	}
)

const (
	InstallFeatureIngressless InstallFeature = "ingressless"
)

func Download(version *semver.Version, name string, featuresToInstall []InstallFeature) (*Runtime, error) {
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
		body, err = io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read runtime definition data: %w", err)
		}
	} else {
		body, err = os.ReadFile(store.RuntimeDefURL)
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

	if runtime.Spec.devMode {
		runtime.Spec.Version = semver.MustParse("v99.99.99")
	}

	filteredComponets := make([]AppDef, 0)
	for i := range runtime.Spec.Components {
		component := runtime.Spec.Components[i]
		if !shouldInstallFeature(featuresToInstall, component.Feature) {
			continue
		}

		if runtime.Spec.Components[i].Type == "kustomize" {
			url := component.URL
			if store.Get().SetDefaultResources {
				url = strings.Replace(url, "manifests/", "manifests/default-resources/", 1)
			}

			component.URL = runtime.Spec.fullURL(url)
		}

		filteredComponets = append(filteredComponets, component)
	}

	runtime.Spec.Components = filteredComponets
	return runtime, nil
}

func Load(fs apfs.FS, filename string) (*Runtime, error) {
	cm := &v1.ConfigMap{}
	if err := fs.ReadYamls(filename, cm); err != nil {
		return nil, fmt.Errorf("failed to load runtime from \"%s\": %w", filename, err)
	}

	data := cm.Data["runtime"]
	runtime := &Runtime{}
	if err := yaml.Unmarshal([]byte(data), runtime); err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime from \"%s\": %w", filename, err)
	}

	for i := range runtime.Spec.Components {
		runtime.Spec.Components[i].URL = runtime.Spec.fullURL(runtime.Spec.Components[i].URL)
	}

	return runtime, nil
}

func (r *Runtime) Save(fs apfs.FS, filename string, config *CommonConfig) error {
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

func (r *Runtime) Install(ctx context.Context, f apkube.Factory, cloneOpts *apgit.CloneOptions, valuesProvider HelmValuesProvider) error {
	return r.Spec.install(ctx, f, cloneOpts, r.Name, valuesProvider)
}

func (r *Runtime) Upgrade(fs apfs.FS, newRt *Runtime, config *CommonConfig) ([]AppDef, error) {
	newComponents, err := r.Spec.upgrade(fs, &newRt.Spec)
	if err != nil {
		return nil, err
	}

	if err := newRt.Save(fs, fs.Join(apstore.Default.BootsrtrapDir, r.Name+".yaml"), config); err != nil {
		return nil, fmt.Errorf("failed to save runtime definition: %w", err)
	}

	return newComponents, nil
}

func (r *RuntimeSpec) install(ctx context.Context, f apkube.Factory, cloneOpts *apgit.CloneOptions, runtimeName string, valuesProvider HelmValuesProvider) error {
	for _, component := range r.Components {
		log.G(ctx).Infof("Creating component \"%s\"", component.Name)
		component.IsInternal = true
		values, err := valuesProvider.GetValues(component.Name)
		if err != nil {
			return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\" application: %w", component.Name, err))
		}

		err = component.CreateApp(ctx, f, cloneOpts, runtimeName, store.Get().CFComponentType, values)
		if err != nil {
			return util.DecorateErrorWithDocsLink(fmt.Errorf("failed to create \"%s\" application: %w", component.Name, err))
		}
	}

	return nil
}

func (r *RuntimeSpec) upgrade(fs apfs.FS, newRt *RuntimeSpec) ([]AppDef, error) {
	log.G().Infof("Upgrading bootstrap specifier")
	argocdDir := fs.Join(apstore.Default.BootsrtrapDir, apstore.Default.ArgoCDName)
	if err := updateKustomization(fs, argocdDir, r.FullSpecifier(), newRt.FullSpecifier()); err != nil {
		return nil, fmt.Errorf("failed to upgrade bootstrap specifier: %w", err)
	}

	newRt.AccessMode = r.AccessMode
	newRt.Cluster = r.Cluster
	newRt.IngressClass = r.IngressClass
	newRt.IngressController = r.IngressController
	newRt.IngressHost = r.IngressHost
	newRt.InternalIngressHost = r.InternalIngressHost
	newRt.Repo = r.Repo

	newComponents := make([]AppDef, 0)
	for _, newComponent := range newRt.Components {
		curComponent := r.component(newComponent.Name)
		if curComponent != nil {
			log.G().Infof("Upgrading \"%s\"", newComponent.Name)
			baseDir := fs.Join(apstore.Default.AppsDir, curComponent.Name, apstore.Default.BaseDir)
			if err := updateKustomization(fs, baseDir, curComponent.URL, newComponent.URL); err != nil {
				return nil, fmt.Errorf("failed to upgrade app \"%s\": %w", curComponent.Name, err)
			}
		} else {
			log.G().Debugf("marking \"%s\" to be created later", newComponent.Name)
			newComponents = append(newComponents, newComponent)
		}
	}

	for _, curComponent := range r.Components {
		newComponent := newRt.component(curComponent.Name)
		if newComponent == nil {
			log.G().Infof("Deleting \"%s\"", curComponent.Name)
			if err := curComponent.delete(fs); err != nil {
				return nil, fmt.Errorf("failed to delete app \"%s\": %w", curComponent.Name, err)
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
	url := r.BootstrapSpecifier
	if store.Get().SetDefaultResources {
		url = strings.Replace(url, "manifests/", "manifests/default-resources/", 1)
	}
	return buildFullURL(url, r.Version, r.devMode)
}

func (r *RuntimeSpec) fullURL(url string) string {
	return buildFullURL(url, r.Version, r.devMode)
}

// A component with no "Feature" value (or "") will always be installed
// when installing a runtime with an empty featuresToInstall (nil or empty slice) - only install base components
// currently we only support ingressless feature, which is being added if the user adds `--accessMode tunnel`
//           this will install the codefresh-tunnel-client component on top of the base installation
func shouldInstallFeature(featuresToInstall []InstallFeature, featureName InstallFeature) bool {
	if featureName == "" {
		return true
	}

	for _, v := range featuresToInstall {
		if v == featureName {
			return true
		}
	}

	return false
}

func (a *AppDef) CreateApp(ctx context.Context, f apkube.Factory, cloneOpts *apgit.CloneOptions, runtimeName, cfType string, optionalValues ...string) error {
	return util.Retry(ctx, &util.RetryOptions{
		Func: func() error {
			newCloneOpts := &apgit.CloneOptions{
				FS:       apfs.Create(memfs.New()),
				Repo:     cloneOpts.Repo,
				Auth:     cloneOpts.Auth,
				Progress: cloneOpts.Progress,
			}
			newCloneOpts.Parse()

			if a.Type == "helm" {
				values := ""
				if len(optionalValues) > 0 {
					values = optionalValues[0]
				}
				return a.createHelmAppDirectly(ctx, newCloneOpts, runtimeName, cfType, values)
			}

			return a.createAppUsingAutopilot(ctx, f, newCloneOpts, runtimeName, cfType)
		},
	})
}

func (a *AppDef) createAppUsingAutopilot(ctx context.Context, f apkube.Factory, cloneOpts *apgit.CloneOptions, runtimeName, cfType string) error {
	timeout := time.Duration(0)
	if a.Wait {
		timeout = store.Get().WaitTimeout
	}

	appCreateOpts := &apcmd.AppCreateOptions{
		CloneOpts:     cloneOpts,
		AppsCloneOpts: &apgit.CloneOptions{},
		ProjectName:   runtimeName,
		AppOpts: &apapp.CreateOptions{
			AppName:       a.Name,
			AppSpecifier:  a.URL,
			AppType:       a.Type,
			DestNamespace: runtimeName,
			Labels: map[string]string{
				util.EscapeAppsetFieldName(store.Get().LabelKeyCFType):     cfType,
				util.EscapeAppsetFieldName(store.Get().LabelKeyCFInternal): strconv.FormatBool(a.IsInternal),
			},
			Annotations: map[string]string{
				util.EscapeAppsetFieldName(store.Get().AnnotationKeySyncWave): strconv.Itoa(a.SyncWave),
			},
			Include: a.Include,
			Exclude: a.Exclude,
		},
		KubeFactory: f,
		Timeout:     timeout,
	}

	return apcmd.RunAppCreate(ctx, appCreateOpts)
}

func (a *AppDef) createHelmAppDirectly(ctx context.Context, cloneOpts *apgit.CloneOptions, runtimeName, cfType string, values string) error {
	r, fs, err := cloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed getting repository while creating helm app: %w", err)
	}

	helmAppPath := cloneOpts.FS.Join(apstore.Default.AppsDir, a.Name, runtimeName, "config_helm.json")
	host, orgRepo, path, gitRef, _, suffix, _ := apaputil.ParseGitUrl(a.URL)
	repoUrl := host + orgRepo + suffix
	config := &HelmConfig{
		Config: apapp.Config{
			AppName:           a.Name,
			UserGivenName:     a.Name,
			DestNamespace:     runtimeName,
			DestServer:        apstore.Default.DestServer,
			SrcRepoURL:        repoUrl,
			SrcPath:           path,
			SrcTargetRevision: gitRef,
			Labels: map[string]string{
				util.EscapeAppsetFieldName(store.Get().LabelKeyCFType):     cfType,
				util.EscapeAppsetFieldName(store.Get().LabelKeyCFInternal): strconv.FormatBool(a.IsInternal),
			},
			Annotations: map[string]string{
				util.EscapeAppsetFieldName(store.Get().AnnotationKeySyncWave): strconv.Itoa(a.SyncWave),
			},
		},
		Values: values,
	}
	err = fs.WriteJson(helmAppPath, config)
	if err != nil {
		return fmt.Errorf("failed to write helm app config file: %w", err)
	}

	commitMsg := fmt.Sprintf("installed app '%s' on project '%s'", a.Name, runtimeName)
	if fs.Root() != "" {
		commitMsg += fmt.Sprintf(" installation-path: '%s'", fs.Root())
	}
	return aputil.PushWithMessage(ctx, r, commitMsg)
}

func (a *AppDef) delete(fs apfs.FS) error {
	return billyUtils.RemoveAll(fs, fs.Join(apstore.Default.AppsDir, a.Name))
}

func updateKustomization(fs apfs.FS, directory, fromURL, toURL string) error {
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
