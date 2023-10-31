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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/templates"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	"github.com/codefresh-io/cli-v2/pkg/util/helm"
	"github.com/codefresh-io/cli-v2/pkg/util/kube"
	"github.com/go-git/go-billy/v5/memfs"

	apfs "github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/chartutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	HelmValidateValuesOptions struct {
		valuesFile  string
		namespace   string
		kubeFactory apkube.Factory
		helm        helm.Helm
		hook        bool
	}

	HelmUpgradeOptions struct {
		runtimeName string
		cloneOpts   *apgit.CloneOptions
		kubeFactory apkube.Factory
	}
)

var (
	ErrRuntimeTokenNotFound = errors.New("runtime token not found")
)

func NewHelmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helm",
		Short: "Helm related commands",
		Args:  cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewHelmValidateValuesCommand())
	cmd.AddCommand(NewHelmUpgradeCommand())

	return cmd
}

func NewHelmValidateValuesCommand() *cobra.Command {
	opts := &HelmValidateValuesOptions{}

	cmd := &cobra.Command{
		Use:     "validate",
		Aliases: []string{"v"},
		Args:    cobra.NoArgs,
		Short:   "Validate helm installation values file",
		Example: util.Doc("<BIN> helm validate --values <values_file.yaml> [--namespace <namespace>] [--version <version>]"),
		PreRun: func(cmd *cobra.Command, _ []string) {
			opts.namespace = cmd.Flag("namespace").Value.String()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runHelmValidate(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("failed validating file \"%s\": %w", opts.valuesFile, err)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.valuesFile, "values", "f", "", "specify values in a YAML file or a URL")
	cmd.Flags().BoolVar(&opts.hook, "hook", false, "set to true when running inside a helm-hook")
	opts.helm = helm.AddFlags(cmd.Flags())
	opts.kubeFactory = apkube.AddFlags(cmd.Flags())

	util.Die(cmd.Flags().MarkHidden("hook"))

	return cmd
}

func NewHelmUpgradeCommand() *cobra.Command {
	opts := &HelmUpgradeOptions{}

	cmd := &cobra.Command{
		Use:     "upgrade",
		Short:   "upgrade a cli-runtime to the new helm-runtime",
		Example: util.Doc("<BIN> helm upgrade [RUNTIME_NAME]"),
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

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runHelmUpgrade(cmd.Context(), opts)
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
	opts.kubeFactory = apkube.AddFlags(cmd.Flags())

	return cmd
}

func runHelmValidate(ctx context.Context, opts *HelmValidateValuesOptions) error {
	log.G(ctx).Infof("Validating helm values file \"%s\"", opts.valuesFile)
	if opts.hook {
		log.G(ctx).Infof("Running in hook-mode")
	}

	values, err := opts.helm.GetValues(opts.valuesFile, !opts.hook)
	if err != nil {
		return fmt.Errorf("failed getting values: %w", err)
	}

	runtimeName, err := helm.PathValue[string](values, "global.runtime.name")
	if err != nil || runtimeName == "" {
		return errors.New("missing \"global.runtime.name\" field")
	}

	log.G(ctx).Debugf("Runtime name: %s", runtimeName)
	if opts.namespace == "" {
		opts.namespace = runtimeName
	}

	err = checkIngress(ctx, opts, values)
	if err != nil {
		return err
	}

	gitProvider, gitApiUrl, err := checkPlatform(ctx, opts, values, runtimeName)
	if err != nil {
		return err
	}

	err = checkGit(ctx, opts, values, gitProvider, gitApiUrl)
	if err != nil {
		return fmt.Errorf("failed validating git credentials data: %w", err)
	}

	log.G(ctx).Infof("Successfuly validated helm values file")
	return nil
}

func checkPlatform(ctx context.Context, opts *HelmValidateValuesOptions, values chartutil.Values, runtimeName string) (platmodel.GitProviders, string, error) {
	codefreshValues, err := values.Table("global.codefresh")
	if err != nil {
		return "", "", err
	}

	err = validateWithRuntimeToken(ctx, opts, codefreshValues, runtimeName)
	if err != nil {
		if err != ErrRuntimeTokenNotFound {
			return "", "", err
		}

		log.G(ctx).Debug("Runtime token not found, looking for user token")
		return validateWithUserToken(ctx, opts, codefreshValues, runtimeName)
	}

	return "", "", nil
}

func validateWithRuntimeToken(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values, runtimeName string) error {
	runtimeToken, _ := kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, store.Get().CFTokenSecret, "token")
	if runtimeToken == "" {
		return ErrRuntimeTokenNotFound
	}

	log.G(ctx).Info("Used runtime token to validate platform reachability")
	cfClient, err := getPlatformClient(ctx, opts, codefreshValues, runtimeToken)
	if err != nil {
		return fmt.Errorf("failed creating codefresh client using runtime token: %v", err)
	}

	_, err = cfClient.V2().Runtime().Get(ctx, runtimeName)
	if err != nil {
		return fmt.Errorf("failed getting runtime from platform: %w", err)
	}

	return nil
}

func validateWithUserToken(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values, runtimeName string) (platmodel.GitProviders, string, error) {
	userToken, err := getUserToken(ctx, opts, codefreshValues)
	if err != nil {
		return "", "", fmt.Errorf("failed getting user token: %w", err)
	}

	log.G(ctx).Info("Using user token to validate platform reachability")
	cfClient, err := getPlatformClient(ctx, opts, codefreshValues, userToken)
	if err != nil {
		return "", "", fmt.Errorf("failed creating codefresh client using user token: %w", err)
	}

	user, err := cfClient.V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return "", "", err
	}

	if !user.IsActiveAccountAdmin() {
		return "", "", fmt.Errorf("user \"%s\" does not have Admin role in account \"%s\"", user.Name, *user.ActiveAccount.Name)
	}

	accountId, _ := helm.PathValue[string](codefreshValues, "accountId")
	if accountId != "" && user.ActiveAccount.ID != accountId {
		return "", "", fmt.Errorf("account mismatch - userToken is for accountId %s (\"%s\"), while \"global.codefresh.accountId\" is %s", user.ActiveAccount.ID, *user.ActiveAccount.Name, accountId)
	}

	log.G(ctx).Debugf("User \"%s\" has Admin role in account \"%s\"", user.Name, *user.ActiveAccount.Name)
	err = checkRuntimeName(ctx, cfClient, runtimeName)
	if err != nil {
		return "", "", err
	}

	var (
		gitProvider platmodel.GitProviders
		gitApiUrl   string
	)

	if user.ActiveAccount.GitProvider != nil {
		gitProvider = *user.ActiveAccount.GitProvider
	}

	if user.ActiveAccount.GitAPIURL != nil {
		gitApiUrl = *user.ActiveAccount.GitAPIURL
	}

	return gitProvider, gitApiUrl, nil
}

func getUserToken(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values) (string, error) {
	userTokenValues, err := codefreshValues.Table("userToken")
	if err != nil {
		return "", errors.New("missing \"global.codefresh.userToken\" field")
	}

	token, _ := helm.PathValue[string](userTokenValues, "token")
	if token != "" {
		log.G(ctx).Debug("Got user token from \"token\" field")
		return token, nil
	}

	secretKeyRef, err := userTokenValues.Table("secretKeyRef")
	if err != nil {
		return "", errors.New("userToken must contain either a \"token\" field, or a \"secretKeyRef\"")
	}

	token, err = getValueFromSecretKeyRef(ctx, opts, secretKeyRef)
	if err != nil {
		return "", fmt.Errorf("failed getting user token from secretKeyRef: %w", err)
	}

	return token, nil
}

func getPlatformClient(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values, cfToken string) (codefresh.Codefresh, error) {
	url, err := helm.PathValue[string](codefreshValues, "url")
	if err != nil || url == "" {
		return nil, errors.New("\"global.codefresh.url\" must be a non-empty string")
	}

	caCert, err := getPlatformCertFile(ctx, opts, codefreshValues)
	if err != nil {
		return nil, fmt.Errorf("failed getting CACert data from \"global.codefresh.tls\": %w", err)
	}

	if caCert != "" {
		defer os.Remove(caCert)
	}

	return cfConfig.NewAdHocClient(ctx, url, cfToken, caCert)
}

func getPlatformCertFile(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values) (string, error) {
	tlsValues, err := codefreshValues.Table("tls.caCerts")
	if err != nil {
		return "", errors.New("missing \"global.codefresh.tls.caCerts\" field")
	}

	create, err := helm.PathValue[bool](tlsValues, "secret.create")
	if err != nil {
		return "", err
	}

	caCertStr := ""
	if create {
		caCertStr, err = helm.PathValue[string](tlsValues, "secret.content")
		if caCertStr == "" || err != nil {
			return "", errors.New("\"global.codefresh.tls.caCert.secret.content\" must be provided when \"create\" is set")
		}

		log.G(ctx).Debug("Got platform certificate from values file")
	} else {
		secretKeyRef, err := tlsValues.Table("secretKeyRef")
		if err != nil {
			return "", fmt.Errorf("failed getting \"global.codefresh.tls.caCert.secretKeyRef\": %w", err)
		}

		caCertStr, err = getValueFromSecretKeyRef(ctx, opts, secretKeyRef)
		if err != nil {
			return "", fmt.Errorf("failed getting caCert from secretKeyRef: %w", err)
		}

		if caCertStr != "" {
			log.G(ctx).Debug("Got platform certificate from secretKeyRef")
		}
	}

	if caCertStr == "" {
		return "", nil
	}

	tmpCaCertFile := path.Join(os.TempDir(), "codefresh-tls-ca.cer")
	err = os.WriteFile(tmpCaCertFile, []byte(caCertStr), 0422)
	if err != nil {
		return "", fmt.Errorf("failed writing platform certificate to temporary path \"%s\": %w", tmpCaCertFile, err)
	}

	return tmpCaCertFile, nil
}

func checkRuntimeName(ctx context.Context, cfClient codefresh.Codefresh, runtimeName string) error {
	_, err := cfClient.V2().Runtime().Get(ctx, runtimeName)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			log.G(ctx).Debugf("Runtime name \"%s\" is available for a new install", runtimeName)
			return nil // runtime does not exist
		}

		return fmt.Errorf("failed to get runtime: %w", err)
	}

	return fmt.Errorf("runtime \"%s\" already exists", runtimeName)
}

func checkIngress(ctx context.Context, opts *HelmValidateValuesOptions, values chartutil.Values) error {
	ingressValues, err := values.Table("global.runtime.ingress")
	if err != nil {
		return errors.New("missing \"global.runtime.ingress\" values")
	}

	ingressEnabled, err := helm.PathValue[bool](ingressValues, "enabled")
	if err != nil {
		return errors.New("missing \"global.runtime.ingress.enabled\" value")
	}

	if ingressEnabled {
		err = checkIngressDef(ctx, opts, ingressValues)
		if err != nil {
			return fmt.Errorf("failed checking ingress data: %w", err)
		}

		log.G(ctx).Debug("Using standard ingress access mode")
		return nil
	}

	tunnelEnabled, err := helm.PathValue[bool](values, "tunnel-client.enabled")
	if err != nil {
		return errors.New("missing \"tunnel-client.enabled\" value")
	}

	if tunnelEnabled {
		accountId, err := helm.PathValue[string](values, "global.codefresh.accountId")
		if accountId == "" || err != nil {
			return errors.New("\"global.codefresh.accountId\" must be provided when using tunnel-client")
		}

		log.G(ctx).Debug("Using tunnel access mode")
		return nil
	}

	ingressUrl, err := helm.PathValue[string](values, "global.runtime.ingressUrl")
	if ingressUrl == "" || err != nil {
		return errors.New("must supply \"global.runtime.ingressUrl\" if both \"global.runtime.ingress.enabled\" and \"tunnel-client.enabled\" are false")
	}

	log.G(ctx).Debug("Using manual ingress set-up")
	return nil
}

func checkIngressDef(ctx context.Context, opts *HelmValidateValuesOptions, ingress chartutil.Values) error {
	hosts, err := helm.PathValue[[]interface{}](ingress, "hosts")
	if err != nil || len(hosts) == 0 {
		return errors.New("\"global.runtime.ingress.hosts\" array must contain an array of strings")
	}

	host, ok := hosts[0].(string)
	if !ok || host == "" {
		return errors.New("\"global.runtime.ingress.hosts\" values must be non-empty strings")
	}

	protocol, _ := helm.PathValue[string](ingress, "protocol")
	if protocol != "https" && protocol != "http" {
		return errors.New("\"global.runtime.ingress.protocol\" value must be https|http")
	}

	className, err := helm.PathValue[string](ingress, "className")
	if err != nil || className == "" {
		return errors.New("\"global.runtime.ingress.className\" values must be a non-empty string")
	}

	skipValidation, _ := helm.PathValue[bool](ingress, "skipValidation")
	if skipValidation {
		return nil
	}

	cs := kube.GetClientSetOrDie(opts.kubeFactory)
	_, err = cs.NetworkingV1().IngressClasses().Get(ctx, className, metav1.GetOptions{})
	if err != nil {
		return err
	}

	url := url.URL{
		Scheme: protocol,
		Host:   host,
	}

	res, err := http.Head(url.String())
	if err != nil {
		return err
	}

	res.Body.Close()
	return nil
}

func checkGit(ctx context.Context, opts *HelmValidateValuesOptions, values chartutil.Values, platGitProvider platmodel.GitProviders, gitApiUrl string) error {
	gitValues, err := values.Table("global.runtime.gitCredentials")
	if gitValues == nil || err != nil {
		log.G(ctx).Debug("No gitCredentials field, skipping git validation")
		return nil
	}

	password, err := getGitPassword(ctx, opts, gitValues)
	if err != nil {
		return fmt.Errorf("failed getting \"global.runtime.gitCredentials.password\": %w", err)
	}

	if password == "" {
		log.G(ctx).Debug("No gitCredentials.Password data, skipping git validation")
		return nil
	}

	username, err := helm.PathValue[string](gitValues, "username")
	if err != nil || username == "" {
		return errors.New("\"global.runtime.gitCredentials.username\" must be a non-empty string")
	}

	if platGitProvider == "" || gitApiUrl == "" {
		log.G(ctx).Debug("No gitProvider data, skipping git validation")
		return nil
	}

	cliGitProvider, err := modelToCliGitProvider(platGitProvider.String())
	if err != nil {
		return fmt.Errorf("invalid gitProvider on account: %w", err)
	}

	caCert, err := getGitCertFile(ctx, values, gitApiUrl)
	if err != nil {
		return err
	}

	if caCert != "" {
		defer os.Remove(caCert)
	}

	provider, err := cfgit.GetProvider(cliGitProvider, gitApiUrl, caCert)
	if err != nil {
		return err
	}

	err = provider.VerifyRuntimeToken(ctx, apgit.Auth{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("failed verifying runtime git token with git server \"%s\": %w", gitApiUrl, err)
	}

	log.G(ctx).Infof("Verified git credentials data with git server \"%s\"", gitApiUrl)
	return nil
}

func getGitCertFile(ctx context.Context, values chartutil.Values, gitApiUrl string) (string, error) {
	certValues, err := values.Table("argo-cd.configs.tls.certificates")
	if certValues == nil || err != nil {
		log.G(ctx).Debug("No certificates in \"argo-cd-configs.tls\" values")
		return "", nil
	}

	u, err := url.Parse(gitApiUrl)
	if err != nil {
		return "", fmt.Errorf("failed parsing gitApiUrl \"%s\": %w", gitApiUrl, err)
	}

	hostname := u.Hostname()
	certificates := certValues.AsMap()
	caCertI, ok := certificates[hostname]
	if !ok {
		log.G(ctx).Debugf("No certificate for git server \"%s\" in \"argo-cd-configs.tls.certificates\"", hostname)
		return "", nil
	}

	caCertStr, ok := caCertI.(string)
	if !ok {
		return "", fmt.Errorf("certificate for git server \"%s\" must be a string value", hostname)
	}

	if caCertStr == "" {
		log.G(ctx).Debugf("empty certificate for git server \"%s\" in \"argo-cd-configs.tls.certificates\"", hostname)
		return "", nil
	}

	log.G(ctx).Debugf("Got certificate for git server \"%s\"", hostname)
	tmpCaCertFile := path.Join(os.TempDir(), hostname+".cer")
	err = os.WriteFile(tmpCaCertFile, []byte(caCertStr), 0422)
	if err != nil {
		return "", fmt.Errorf("failed writing git server certificate to temporary path \"%s\": %w", tmpCaCertFile, err)
	}

	return tmpCaCertFile, nil
}

func getGitPassword(ctx context.Context, opts *HelmValidateValuesOptions, git chartutil.Values) (string, error) {
	password, _ := helm.PathValue[string](git, "password.value")
	if password != "" {
		log.G(ctx).Debug("Got git password from \"value\" field")
		return password, nil
	}

	secretKeyRef, err := git.Table("password.secretKeyRef")
	if err != nil {
		log.G(ctx).Debug("No git password information in \"value\" or \"secretKeyRef\" fields")
		return "", nil
	}

	password, err = getValueFromSecretKeyRef(ctx, opts, secretKeyRef)
	if err != nil {
		log.G(ctx).Debugf("Failed getting git password from secretKeyRef: %s", err.Error())
		return "", err
	}

	if password != "" {
		log.G(ctx).Debug("Got git password from \"secretKeyRef\" field")
	}

	return password, nil
}

func getValueFromSecretKeyRef(ctx context.Context, opts *HelmValidateValuesOptions, secretKeyRef chartutil.Values) (string, error) {
	name, err := helm.PathValue[string](secretKeyRef, "name")
	if name == "" || err != nil {
		return "", nil
	}

	key, err := helm.PathValue[string](secretKeyRef, "key")
	if key == "" || err != nil {
		return "", nil
	}

	return kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, name, key)
}

func filterOnlyClidRuntime(rt *platmodel.Runtime) bool {
	return rt.InstallationType == platmodel.InstallationTypeCli
}

func runHelmUpgrade(ctx context.Context, opts *HelmUpgradeOptions) error {
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
	sha, err := srcRepo.Persist(ctx, &apgit.PushOptions{
		CommitMsg: "moved git sources to internal-shared-config",
	})
	if err != nil {
		return fmt.Errorf("failed pushing changes to installation repo: %w", err)
	}

	log.G(ctx).Infof("Pushed changes to installation repo %q, sha: %s", *runtime.Repo, sha)
	sha, err = destRepo.Persist(ctx, &apgit.PushOptions{
		CommitMsg: "moved git sources from installation repo",
	})
	if err != nil {
		return fmt.Errorf("failed pushing changes to internal-shared-config repo: %w", err)
	}

	log.G(ctx).Infof("Pushed changes to shared-config-repo %q, sha: %s", *runtime.Repo, sha)
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

	for cluster, glob := range globs {
		err = moveClusterGitSources(srcFs, destFs, glob, cluster, runtimeName)
		if err != nil {
			return err
		}
	}

	return nil
}

func moveClusterGitSources(srcFs, destFs apfs.FS, glob, cluster, runtimeName string) error {
	if cluster == runtimeName {
		cluster = "in-cluster"
	}

	internalConfigApp := &argocdv1alpha1.Application{}
	internalConfigFilename := destFs.Join("runtimes", runtimeName, cluster+".yaml")
	err := destFs.ReadYamls(internalConfigFilename, internalConfigApp)
	if err != nil {
		return fmt.Errorf("failed reading internal config file: %w", err)
	}

	includeStr := internalConfigApp.Spec.Source.Directory.Include
	includeArr := strings.Split(includeStr[1:len(includeStr)-1], ",")

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
			includeArr = append(includeArr, relPath)
		}
	}

	internalConfigApp.Spec.Source.Directory.Include = fmt.Sprintf("{%s}", strings.Join(includeArr, ","))
	err = destFs.WriteYamls(internalConfigFilename, internalConfigApp)
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

	relPath := destFs.Join(runtimeName, config.AppName+".yaml")
	fullPAth := destFs.Join("resources", relPath)
	err = billyUtils.WriteFile(destFs, fullPAth, destYaml, 0666)
	if err != nil {
		return "", fmt.Errorf("failed writing git source: %w", err)
	}

	err = srcFs.Remove(configPath)
	if err != nil {
		return "", fmt.Errorf("failed removing config_dir.json: %w", err)
	}

	return relPath, nil
}
