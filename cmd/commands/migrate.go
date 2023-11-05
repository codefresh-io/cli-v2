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

package commands

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/isc"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/templates"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	"github.com/codefresh-io/cli-v2/pkg/util/helm"
	"github.com/codefresh-io/cli-v2/pkg/util/kube"
	"github.com/go-git/go-billy/v5/memfs"

	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	apfs "github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	apiextv1 "github.com/kubewarden/k8s-objects/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

type (
	MigrateOptions struct {
		runtimeName string
		cloneOpts   *apgit.CloneOptions
		helm        helm.Helm
		kubeContext string
		kubeFactory apkube.Factory
	}
)

func NewMigrateCommand() *cobra.Command {
	opts := &MigrateOptions{}

	cmd := &cobra.Command{
		Use:     "migrate",
		Short:   "migrate a cli-runtime to the new helm-runtime",
		Example: util.Doc("<BIN> helm migrate [RUNTIME_NAME]"),
		Args:    cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()
			err = cfConfig.RequireAuthentication(cmd, args)
			if err != nil {
				return err
			}

			opts.runtimeName, err = ensureRuntimeName(ctx, args, filterOnlyClidRuntime)
			if err != nil {
				return err
			}

			opts.kubeContext, err = getKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runHelmMigrate(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("failed upgraring runtime %q: %w", opts.runtimeName, err)
			}

			return nil
		},
	}

	opts.cloneOpts = apu.AddRepoFlags(cmd, &apu.CloneFlagsOptions{
		CreateIfNotExist: false,
		CloneForWrite:    true,
		Optional:         false,
	})
	opts.helm, _ = helm.AddFlags(cmd.Flags())
	opts.kubeFactory = apkube.AddFlags(cmd.Flags())

	return cmd
}

func runHelmMigrate(ctx context.Context, opts *MigrateOptions) error {
	runtime, err := getCliRuntime(ctx, opts.runtimeName)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Got runtime data %q", opts.runtimeName)
	user, err := cfConfig.NewClient().V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return fmt.Errorf("failed getting current user: %w", err)
	}

	log.G(ctx).Infof("Got user data for %q", user.Name)
	srcCloneOpts := &apgit.CloneOptions{
		Provider: user.ActiveAccount.GitProvider.String(),
		Repo:     *runtime.Repo,
		Auth:     opts.cloneOpts.Auth,
		FS:       opts.cloneOpts.FS,
	}
	srcCloneOpts.Parse()
	srcRepo, srcFs, err := srcCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed getting installation repo: %w", err)
	}

	log.G(ctx).Infof("Cloned installation repo %q", *runtime.Repo)
	destCloneOpts := &apgit.CloneOptions{
		Provider: user.ActiveAccount.GitProvider.String(),
		Repo:     *user.ActiveAccount.SharedConfigRepo,
		Auth:     opts.cloneOpts.Auth,
		FS:       apfs.Create(memfs.New()),
	}
	destCloneOpts.Parse()
	destRepo, destFs, err := destCloneOpts.GetRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed getting shared config repo: %w", err)
	}

	log.G(ctx).Infof("Cloned internal-shared-config repo %q", *user.ActiveAccount.SharedConfigRepo)
	err = moveGitSources(srcFs, destFs, opts.runtimeName)
	if err != nil {
		return fmt.Errorf("failed moving git sources: %w", err)
	}

	log.G(ctx).Infof("moved all git-sources from installation repo to shared-config-repo")

	err = moveArgoRollouts(srcFs, destFs, opts, *runtime.Metadata.Namespace)
	if err != nil {
		return fmt.Errorf("failed moving argo-rollouts: %w", err)
	}

	sha, err := srcRepo.Persist(ctx, &apgit.PushOptions{
		CommitMsg: "moved resources to internal-shared-config repo",
	})
	if err != nil {
		return fmt.Errorf("failed pushing changes to installation repo: %w", err)
	}

	log.G(ctx).Infof("Pushed changes to installation repo %q, sha: %s", *user.ActiveAccount.SharedConfigRepo, sha)
	sha, err = destRepo.Persist(ctx, &apgit.PushOptions{
		CommitMsg: "moved resources from installation repo",
	})
	if err != nil {
		return fmt.Errorf("failed pushing changes to internal-shared-config repo: %w", err)
	}

	log.G(ctx).Infof("Pushed changes to shared-config-repo %q, sha: %s", *runtime.Repo, sha)
	log.G(ctx).Infof("Done migrating resources from %q to %q", *runtime.Repo, *user.ActiveAccount.SharedConfigRepo)

	err = removeFromCluster(ctx, *runtime.Metadata.Namespace, opts.kubeContext, srcCloneOpts, opts.kubeFactory)
	if err != nil {
		return fmt.Errorf("failed removing runtime from cluster: %w", err)
	}

	log.G(ctx).Infof("Uninstalled runtime %q", opts.runtimeName)
	return nil
}

func getCliRuntime(ctx context.Context, runtimeName string) (*platmodel.Runtime, error) {
	runtime, err := getRuntime(ctx, runtimeName)
	if err != nil {
		return nil, fmt.Errorf("failed getting runtime: %w", err)
	}

	if runtime.InstallationType != platmodel.InstallationTypeCli {
		return nil, fmt.Errorf("runtime %q is not a cli-runtime", runtimeName)
	}

	if runtime.Repo == nil {
		return nil, fmt.Errorf("runtime %q does not have an installation repo", runtimeName)
	}

	return runtime, nil
}

func getAppsetGlobs(srcFs apfs.FS) (map[string]string, error) {
	res := make(map[string]string)
	projects, err := billyUtils.Glob(srcFs, "/projects/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed getting projects: %w", err)
	}

	for _, projectFile := range projects {
		_, appSet, err := getProjectInfoFromFile(srcFs, projectFile)
		if err != nil {
			return nil, fmt.Errorf("failed getting project info from file %q: %w", projectFile, err)
		}

		generators := appSet.Spec.Generators
		for _, generator := range generators {
			if generator.Git == nil {
				continue
			}

			for _, file := range generator.Git.Files {
				if strings.HasSuffix(file.Path, "config_dir.json") {
					res[appSet.Name] = file.Path
				}
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed getting globs from projects directory: %w", err)
	}

	return res, nil
}

func moveGitSources(srcFs, destFs apfs.FS, runtimeName string) error {
	globs, err := getAppsetGlobs(srcFs)
	if err != nil {
		return err
	}

	for clusterName, glob := range globs {
		err = moveClusterGitSources(srcFs, destFs, glob, runtimeName, clusterName)
		if err != nil {
			return err
		}
	}

	return nil
}

func moveClusterGitSources(srcFs, destFs apfs.FS, glob, runtimeName, clusterName string) error {
	if clusterName == runtimeName {
		clusterName = store.Get().InClusterName
	}

	clusterApp, err := isc.ReadClusterConfigApp(destFs, runtimeName, clusterName)
	if err != nil {
		return fmt.Errorf("failed reading cluster config app: %w", err)
	}

	configs, err := billyUtils.Glob(srcFs, glob)
	if err != nil {
		return fmt.Errorf("failed getting git sources from %q: %w", glob, err)
	}

	for _, configPath := range configs {
		relPath, err := moveSingleGitSource(srcFs, destFs, configPath, runtimeName)
		if err != nil {
			return fmt.Errorf("failed moving git-source %q: %w", configPath, err)
		}

		if relPath != "" {
			clusterApp.AddInclude(relPath)
		}
	}

	err = clusterApp.Write()
	if err != nil {
		return fmt.Errorf("failed writing internal config file: %w", err)
	}

	return nil
}

func moveSingleGitSource(srcFs, destFs apfs.FS, configPath, runtimeName string) (string, error) {
	config := &templates.GitSourceConfig{}
	err := srcFs.ReadJson(configPath, config)
	if err != nil {
		return "", fmt.Errorf("failed reading config_dir.json: %w", err)
	}

	if config.Labels[store.Get().LabelFieldCFType] != store.Get().CFGitSourceType {
		return "", nil
	}

	config.RuntimeName = runtimeName
	for key, value := range config.Annotations {
		if strings.Contains(key, "-") {
			newKey := strings.ReplaceAll(key, "-", "_")
			config.Annotations[newKey] = value
			delete(config.Annotations, key)
		}
	}

	destYaml, err := templates.RenderGitSource(config)
	if err != nil {
		return "", fmt.Errorf("failed rendering git source: %w", err)
	}

	path, err := writeYamlInIsc(destFs, config.AppName, runtimeName, destYaml)
	if err != nil {
		return "", fmt.Errorf("failed writing git source: %w", err)
	}

	err = srcFs.Remove(configPath)
	if err != nil {
		return "", fmt.Errorf("failed removing config_dir.json: %w", err)
	}

	return path, nil
}

func moveArgoRollouts(srcFs, destFs apfs.FS, opts *MigrateOptions, runtimeNamespace string) error {
	rolloutsOverlaysPath := srcFs.Join("apps", "rollouts", "overlays")
	rolloutsOverlays, err := srcFs.ReadDir(rolloutsOverlaysPath)
	if err != nil {
		return fmt.Errorf("failed reading rollouts overlays: %w", err)
	}

	var clusterNames []string
	for _, overlay := range rolloutsOverlays {
		if overlay.IsDir() && overlay.Name() != opts.runtimeName {
			clusterNames = append(clusterNames, overlay.Name())
		}
	}

	for _, clusterName := range clusterNames {
		err = moveClusterArgoRollouts(srcFs, destFs, opts, clusterName)
		if err != nil {
			return fmt.Errorf("failed moving argo-rollouts: %w", err)
		}

		err = moveClusterRolloutReporter(srcFs, destFs, opts.runtimeName, runtimeNamespace, clusterName)
		if err != nil {
			return fmt.Errorf("failed moving rollout-reporter: %w", err)
		}
	}

	return nil
}

func moveClusterArgoRollouts(srcFs, destFs apfs.FS, opts *MigrateOptions, clusterName string) error {
	rolloutsPath, err := createClusterArgoRollouts(destFs, opts, clusterName)
	if err != nil {
		return fmt.Errorf("failed creating argo-rollouts: %w", err)
	}

	err = addPathToInclude(destFs, opts.runtimeName, clusterName, rolloutsPath)
	if err != nil {
		return fmt.Errorf("failed adding path to include: %w", err)
	}

	overlayPath := srcFs.Join("apps", "rollouts", "overlays", clusterName)
	err = billyUtils.RemoveAll(srcFs, overlayPath)
	if err != nil {
		return fmt.Errorf("failed removing config_dir.json: %w", err)
	}

	return nil
}

func createClusterArgoRollouts(destFs apfs.FS, opts *MigrateOptions, clusterName string) (string, error) {
	appName := addSuffix(clusterName, "-"+store.Get().RolloutResourceName, 63)
	repoURL, targetRevision, err := opts.helm.GetDependency("argo-rollouts")
	if err != nil {
		return "", fmt.Errorf("failed getting argo-rollouts dependency: %w", err)
	}

	destYaml, err := templates.RenderArgoRollouts(&templates.ArgoRolloutsConfig{
		AppName:       appName,
		ClusterName:   clusterName,
		RepoURL:       repoURL,
		TargetVersion: targetRevision,
	})
	if err != nil {
		return "", fmt.Errorf("failed rendering argo-rollouts: %w", err)
	}

	path, err := writeYamlInIsc(destFs, appName, opts.runtimeName, destYaml)
	if err != nil {
		return "", fmt.Errorf("failed writing argo-rollouts: %w", err)
	}

	return path, nil
}

func moveClusterRolloutReporter(srcFs, destFs apfs.FS, runtimeName, runtimeNamespace, clusterName string) error {
	reporterPath, err := createClusterRolloutReporter(destFs, runtimeName, runtimeNamespace, clusterName)
	if err != nil {
		return fmt.Errorf("failed creating rollout-reporter: %w", err)
	}

	err = addPathToInclude(destFs, runtimeName, store.Get().InClusterName, reporterPath)
	if err != nil {
		return fmt.Errorf("failed adding path to include: %w", err)
	}

	rolloutReporterPath := srcFs.Join("apps", "rollout-reporter", runtimeName, "resources")
	esPath := srcFs.Join(rolloutReporterPath, fmt.Sprintf("%s-event-source.yaml", clusterName))
	err = srcFs.Remove(esPath)
	if err != nil {
		return fmt.Errorf("failed removing event-source: %w", err)
	}

	sensorPath := srcFs.Join(rolloutReporterPath, fmt.Sprintf("%s-sensor.yaml", clusterName))
	err = srcFs.Remove(sensorPath)
	if err != nil {
		return fmt.Errorf("failed removing sensor: %w", err)
	}

	return nil
}

func createClusterRolloutReporter(destFs apfs.FS, runtimeName, runtimeNamesapce, clusterName string) (string, error) {
	name := addSuffix(clusterName, "-"+store.Get().RolloutReporterName, 63)
	triggerUrl, err := url.JoinPath(cfConfig.GetCurrentContext().URL, store.Get().EventReportingEndpoint)
	if err != nil {
		return "", err
	}

	destYaml, err := templates.RenderRolloutReporter(&templates.RolloutReporterConfig{
		Name:          name,
		Namespace:     runtimeNamesapce,
		ClusterName:   clusterName,
		EventEndpoint: triggerUrl,
	})
	if err != nil {
		return "", fmt.Errorf("failed rendering argo-rollouts: %w", err)
	}

	path, err := writeYamlInIsc(destFs, name, runtimeName, destYaml)
	if err != nil {
		return "", fmt.Errorf("failed writing argo-rollouts: %w", err)
	}

	return path, nil
}

func writeYamlInIsc(destFs apfs.FS, fileName, runtimeName string, data []byte) (string, error) {
	relPath := destFs.Join(runtimeName, fileName+".yaml")
	fullPAth := destFs.Join("resources", relPath)
	err := billyUtils.WriteFile(destFs, fullPAth, data, 0666)
	if err != nil {
		return "", fmt.Errorf("failed writing %q resource: %w", fileName, err)
	}

	return relPath, nil
}

func addPathToInclude(destFs apfs.FS, runtimeName, clusterName, path string) error {
	clusterApp, err := isc.ReadClusterConfigApp(destFs, runtimeName, clusterName)
	if err != nil {
		return fmt.Errorf("failed reading cluster config app: %w", err)
	}

	clusterApp.AddInclude(path)
	err = clusterApp.Write()
	if err != nil {
		return fmt.Errorf("failed writing internal config file: %w", err)
	}

	return nil
}

func addSuffix(str, suffix string, length int) string {
	if len(str)+len(suffix) < length {
		return str + suffix
	}

	return str[:length-len(suffix)] + suffix
}

func removeFromCluster(ctx context.Context, runtimeNamespace, kubeContext string, cloneOptions *apgit.CloneOptions, kubeFactory apkube.Factory) error {
	err := switchSecretsLabel(ctx, kubeFactory, runtimeNamespace, apstore.Default.LabelKeyAppManagedBy, apstore.Default.LabelValueManagedBy, "codefresh")
	if err != nil {
		return fmt.Errorf("failed preserving codefresh token secret: %w", err)
	}

	err = switchSecretsLabel(ctx, kubeFactory, runtimeNamespace, store.Get().LabelGitIntegrationTypeKey, store.Get().LabelGitIntegrationTypeValue, "helm-migration")
	if err != nil {
		return fmt.Errorf("failed preserving git-integration secrets: %w", err)
	}

	err = apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
		Namespace:       runtimeNamespace,
		KubeContextName: kubeContext,
		Timeout:         store.Get().WaitTimeout,
		CloneOptions:    cloneOptions,
		KubeFactory:     kubeFactory,
		Force:           true,
		FastExit:        false,
	})
	if err != nil {
		return fmt.Errorf("failed uninstalling runtime: %w", err)
	}

	err = runPostUninstallCleanup(ctx, kubeFactory, runtimeNamespace)
	if err != nil {
		return fmt.Errorf("failed cleaning up after uninstall: %w", err)
	}

	err = switchSecretsLabel(ctx, kubeFactory, runtimeNamespace, store.Get().LabelGitIntegrationTypeKey, "helm-migration", store.Get().LabelGitIntegrationTypeValue)
	if err != nil {
		return fmt.Errorf("failed restoring git-integration secrets: %w", err)
	}

	err = patchCrds(ctx, kubeFactory)
	if err != nil {
		return fmt.Errorf("failed updating argoproj CRDs: %w", err)
	}

	log.G(ctx).Infof("Uninstalled runtime from cluster")
	
	
	return nil
}

func switchSecretsLabel(ctx context.Context, kubeFactory apkube.Factory, namespace, labelKey, oldValue, newValue string) error {
	secretsInterface := kube.GetClientSetOrDie(kubeFactory).CoreV1().Secrets(namespace)
	secrets, err := secretsInterface.List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelKey, oldValue),
	})
	if err != nil {
		return fmt.Errorf("failed getting secrets: %w", err)
	}

	for _, secret := range secrets.Items {
		_, err := secretsInterface.Patch(
			ctx,
			secret.Name,
			types.StrategicMergePatchType,
			[]byte(getLabelPatch(labelKey, newValue)),
			metav1.PatchOptions{},
		)
		if err != nil {
			return fmt.Errorf("failed patching secret %q: %w", secret.Name, err)
		}
	}

	return nil
}

func patchCrds(ctx context.Context, kubeFactory apkube.Factory) error {
	gvr := schema.GroupVersionResource(apiextv1.SchemeGroupVersion.WithResource("customresourcedefinitions"))
	crdInterface := kube.GetDynamicClientOrDie(kubeFactory).Resource(gvr)
	crds, err := crdInterface.List(ctx, metav1.ListOptions{

	})
	if err != nil {
		return fmt.Errorf("failed listing crds: %w", err)
	}

	for _, crd := range crds.Items {
		if !strings.HasSuffix(crd.GetName(), "argoproj.io") { 
			continue
		}

		_, err := crdInterface.Patch(
			ctx,
			crd.GetName(),
			types.StrategicMergePatchType,
			[]byte(getLabelPatch(apstore.Default.LabelKeyAppManagedBy, "Helm")),
			metav1.PatchOptions{},
		)
		if err != nil {
			return fmt.Errorf("failed patching crd %q: %w", crd.GetName(), err)
		}

		log.G(ctx).Debugf("Patched crd %q", crd.GetName())
	}

	return nil
}

func getLabelPatch(key, value string) string {
	return fmt.Sprintf(`{ "metadata": { "labels": { "%s": "%s" } } }`, key, value)
}
