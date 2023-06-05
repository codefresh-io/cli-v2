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

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/cli-v2/pkg/util/helm"
	"github.com/codefresh-io/cli-v2/pkg/util/kube"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	platmodel "github.com/codefresh-io/go-sdk/pkg/codefresh/model"
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
)

const (
	CODEFRESH_TOKEN = "codefresh-token"
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

func runHelmValidate(ctx context.Context, opts *HelmValidateValuesOptions) error {
	log.G(ctx).Infof("Validating helm file \"%s\"", opts.valuesFile)
	if opts.hook {
		log.G(ctx).Infof("Running in hook-mode")
	}

	values, err := opts.helm.GetValues(opts.valuesFile)
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

	accountId, err := helm.PathValue[string](values, "global.codefresh.accountId")
	if err != nil {
		return err
	}

	err = checkIngress(ctx, opts, values, accountId)
	if err != nil {
		return err
	}

	gitProvider, gitApiUrl, err := checkPlatform(ctx, opts, values, accountId, runtimeName)
	if err != nil {
		return err
	}

	err = checkGit(ctx, opts, values, gitProvider, gitApiUrl)
	if err != nil {
		return fmt.Errorf("failed validating git credentials data: %w", err)
	}

	log.G(ctx).Infof("Successfuly validated helm file")
	return nil
}

func checkPlatform(ctx context.Context, opts *HelmValidateValuesOptions, values chartutil.Values, accountId, runtimeName string) (platmodel.GitProviders, string, error) {
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
		return validateWithUserToken(ctx, opts, codefreshValues, accountId, runtimeName)
	}

	return "", "", nil
}

func validateWithRuntimeToken(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values, runtimeName string) error {
	runtimeToken, _ := kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, CODEFRESH_TOKEN, "token")
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

func validateWithUserToken(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values, accountId, runtimeName string) (platmodel.GitProviders, string, error) {
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

	if user.IsAdmin == nil || !*user.IsAdmin {
		return "", "", fmt.Errorf("user \"%s\" does not have Admin role in account \"%s\"", user.Name, *user.ActiveAccount.Name)
	}

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
		if err != nil {
			return "", fmt.Errorf("failed getting \"global.codefresh.tls.caCert.secret.content\": %w", err)
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

		log.G(ctx).Debug("Got platform certificate from secretKeyRef")
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

func checkIngress(ctx context.Context, opts *HelmValidateValuesOptions, values chartutil.Values, accountId string) error {
	ingressValues, err := values.Table("global.runtime.ingress")
	if err != nil {
		return err
	}

	ingressEnabled, err := helm.PathValue[bool](ingressValues, "enabled")
	if err != nil {
		return err
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
		return err
	}

	if tunnelEnabled {
		if accountId == "" {
			return errors.New("\"global.codefresh.accountId\" must be provided when using tunnel-client")
		}

		log.G(ctx).Debug("Using tunnel access mode")
		return nil
	}

	ingressUrl, err := helm.PathValue[string](values, "global.runtime.ingressUrl")
	if err != nil {
		return err
	}

	if ingressUrl != "" {
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

	url := url.URL{
		Scheme: protocol,
		Host:   host,
	}

	res, err := http.Head(url.String())
	if err != nil {
		return err
	}

	res.Body.Close()
	className, err := helm.PathValue[string](ingress, "className")
	if err != nil || className == "" {
		return errors.New("\"global.runtime.ingress.className\" values must be a non-empty string")
	}

	cs := kube.GetClientSetOrDie(opts.kubeFactory)
	_, err = cs.NetworkingV1().IngressClasses().Get(ctx, className, metav1.GetOptions{})
	return err
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

	return provider.VerifyRuntimeToken(ctx, apgit.Auth{
		Username: username,
		Password: password,
	})
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
		log.G(ctx).Debugf("No certificate for \"%s\" in \"argo-cd-configs.tls.certificates\"", hostname)
		return "", nil
	}

	caCertStr, ok := caCertI.(string)
	if !ok {
		return "", fmt.Errorf("certificate for git server host \"%s\" must be a string value", hostname)
	}

	if caCertStr == "" {
		log.G(ctx).Debugf("empty certificate for \"%s\" in \"argo-cd-configs.tls.certificates\"", hostname)
		return "", nil
	}

	log.G(ctx).Debug("Got git server certificate from values file")
	tmpCaCertFile := path.Join(os.TempDir(), hostname + ".cer")
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
		log.G(ctx).Debug("\"secretKeyRef.name\" does not contain a valid string value")
		return "", nil
	}

	key, err := helm.PathValue[string](secretKeyRef, "key")
	if key == "" || err != nil {
		log.G(ctx).Debug("\"secretKeyRef.key\" does not contain a valid string value")
		return "", nil
	}

	return kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, name, key)
}
