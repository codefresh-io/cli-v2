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
		version     string
		devel       bool
		namespace   string
		kubeFactory apkube.Factory
		helm        helm.Helm
	}
)

func NewHelmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helm",
		Short: "helm blah blah",
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
		Example: util.Doc("<BIN> helm validate --values <values_file.yaml>"),
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
	opts.helm = helm.AddFlags(cmd.Flags())
	opts.kubeFactory = apkube.AddFlags(cmd.Flags())
	return cmd
}

func runHelmValidate(ctx context.Context, opts *HelmValidateValuesOptions) error {
	log.G(ctx).Infof("Validating helm file \"%s\"", opts.valuesFile)
	values, err := opts.helm.GetValues(opts.valuesFile)
	if err != nil {
		return err
	}

	runtimeName, err := helm.PathValue[string](values, "global.runtime.name")
	if err != nil || runtimeName == "" {
		return err
	}

	log.G(ctx).Debugf("Runtime name: %s", runtimeName)
	if opts.namespace == "" {
		opts.namespace = runtimeName
	}

	codefreshValues, err := values.Table("global.codefresh")
	if err != nil {
		return errors.New("missing \"global.codefresh\" field")
	}

	cfClient, err := getPlatformClient(ctx, opts, codefreshValues)
	if err != nil {
		return err
	}

	log.G(ctx).Debug("Got platform client")
	user, err := checkUserPermission(ctx, cfClient)
	if err != nil {
		return err
	}

	accountId, _ := helm.PathValue[string](values, "global.codefresh.accountId")
	if accountId != "" && user.ActiveAccount.ID != accountId {
		return fmt.Errorf("account mismatch - userToken is for accountId %s (\"%s\"), while \"global.codefresh.accountId\" is %s", user.ActiveAccount.ID, *user.ActiveAccount.Name, accountId)
	}

	err = checkRuntimeName(ctx, cfClient, runtimeName)
	if err != nil {
		return err
	}

	ingressValues, err := values.Table("global.runtime.ingress")
	if err != nil {
		return errors.New("missing \"global.runtime.ingress\" field")
	}

	enabled, err := helm.PathValue[bool](ingressValues, "enabled")
	if err != nil {
		return err
	}

	if enabled {
		err = checkIngress(ctx, opts, ingressValues)
		if err != nil {
			return err
		}
	} else {
		if accountId == "" {
			return errors.New("\"global.codefresh.accountId\" must be provided when not using an ingress")
		}
	}

	gitValues, err := values.Table("global.runtime.gitCredentials")
	if err != nil {
		log.G(ctx).Debug("No gitCredentials field, skipping git validation")
		log.G(ctx).Infof("Successfuly validated helm file - will install runtime \"%s\" to account \"%s\"", runtimeName, *user.ActiveAccount.Name)
		return nil
	}

	err = checkGitToken(ctx, opts, user, gitValues)
	if err != nil {
		log.G(ctx).Errorf("failed validating git credentials data")
		return err
	}

	log.G(ctx).Infof("Successfuly validated helm file - will install runtime \"%s\" to account \"%s\"", runtimeName, *user.ActiveAccount.Name)
	return nil
}

func getPlatformClient(ctx context.Context, opts *HelmValidateValuesOptions, codefreshValues chartutil.Values) (codefresh.Codefresh, error) {
	userTokenValues, err := codefreshValues.Table("userToken")
	if err != nil {
		return nil, errors.New("missing \"global.codefresh.userToken\" field")
	}

	userToken, err := getUserToken(ctx, opts, userTokenValues)
	if err != nil || userToken == "" {
		return nil, fmt.Errorf("missing \"global.codefresh.userToken\" value or secretKeyRef fields: %w", err)
	}

	url, err := helm.PathValue[string](codefreshValues, "url")
	if err != nil || url == "" {
		return nil, errors.New("\"global.codefresh.url\" must be a non-empty string")
	}

	return cfConfig.NewAdHocClient(ctx, url, userToken)
}

func getUserToken(ctx context.Context, opts *HelmValidateValuesOptions, userTokenValues chartutil.Values) (string, error) {
	token, err := helm.PathValue[string](userTokenValues, "token")
	if err != nil {
		log.G(ctx).Debug("Got user token from \"value\" field")
		return "", err
	}

	if token != "" {
		return token, nil
	}

	secretKeyRef, err := userTokenValues.Table("secretKeyRef")
	if err != nil {
		return "", errors.New("userToken must contain either a \"token\" field, or a \"secretKeyRef\"")
	}

	token, err = getValueFromSecretKeyRef(ctx, opts, secretKeyRef)
	if err != nil {
		log.G(ctx).Debugf("Failed getting user token from secretKeyRef: %s", err.Error())
		return "", err
	}

	if token == "" {
		log.G(ctx).Debug("No user token in value or secretKeyRef fields")
	} else {
		log.G(ctx).Debug("Got user token from \"secretKeyRef\" field")
	}

	return token, nil
}

func checkUserPermission(ctx context.Context, cfClient codefresh.Codefresh) (*platmodel.User, error) {
	user, err := cfClient.V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return nil, err
	}

	if user.IsAdmin == nil || !*user.IsAdmin {
		return nil, fmt.Errorf("user \"%s\" does not have Admin role in account \"%s\"", user.Name, *user.ActiveAccount.Name)
	}

	log.G(ctx).Debugf("User \"%s\" has Admin role in account \"%s\"", user.Name, *user.ActiveAccount.Name)
	return user, nil
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

func checkIngress(ctx context.Context, opts *HelmValidateValuesOptions, ingress chartutil.Values) error {
	hosts, err := helm.PathValue[[]interface{}](ingress, "hosts")
	if err != nil {
		return errors.New("\"global.runtime.ingress.hosts\" array must contain an array of strings")
	}

	if len(hosts) == 0 {
		return errors.New("\"global.runtime.ingress.hosts\" array must contain values")
	}

	host, ok := hosts[0].(string)
	if !ok || host == "" {
		return errors.New("\"global.runtime.ingress.hosts\" values must be non-empty strings")
	}

	protocol, err := helm.PathValue[string](ingress, "protocol")
	if err != nil || (protocol != "https" && protocol != "http") {
		return errors.New("\"global.runtime.ingress.protocol\" value must be https|http")
	}

	url := url.URL{
		Scheme: protocol,
		Host:   host,
	}

	res, err := http.Get(url.String())
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
	if err != nil {
		return fmt.Errorf("\"global.codefresh.ingress.className: %s\" was not found on cluster", className)
	}

	return nil
}

func checkGitToken(ctx context.Context, opts *HelmValidateValuesOptions, user *platmodel.User, git chartutil.Values) error {
	password, err := getGitPassword(ctx, opts, git)
	if err != nil {
		return fmt.Errorf("failed getting \"global.runtime.gitCredentials.password\": %w", err)
	}

	if password == "" {
		log.G(ctx).Debug("No gitCredentials.Password data, skipping git validation")
		return nil
	}

	username, err := helm.PathValue[string](git, "username")
	if err != nil || username == "" {
		return errors.New("\"global.runtime.gitCredentials.username\" must be a non-empty string")
	}

	if user.ActiveAccount.GitProvider == nil {
		return fmt.Errorf("account \"%s\" is missing gitProvider data", *user.ActiveAccount.Name)
	}

	if user.ActiveAccount.GitAPIURL == nil {
		return fmt.Errorf("account \"%s\" is missing gitApiUrl data", *user.ActiveAccount.Name)
	}

	platGitProvider, gitApiUrl := *user.ActiveAccount.GitProvider, *user.ActiveAccount.GitAPIURL
	cliGitProvider, err := modelToCliGitProvider(platGitProvider.String())
	if err != nil {
		return fmt.Errorf("invalid gitProvider on account: %w", err)
	}

	provider, err := cfgit.GetProvider(cliGitProvider, gitApiUrl, "")
	if err != nil {
		return err
	}

	return provider.VerifyRuntimeToken(ctx, apgit.Auth{
		Username: username,
		Password: password,
	})
}

func getGitPassword(ctx context.Context, opts *HelmValidateValuesOptions, git chartutil.Values) (string, error) {
	password, _ := helm.PathValue[string](git, "password.value")
	if password != "" {
		log.G(ctx).Debug("Got git password from \"value\" field")
		return password, nil
	}

	secretKeyRef, err := git.Table("password.secretKeyRef")
	if err != nil {
		log.G(ctx).Debug("No git password in value or secretKeyRef fields")
		return "", nil
	}

	password, err = getValueFromSecretKeyRef(ctx, opts, secretKeyRef)
	if err != nil {
		log.G(ctx).Debugf("Failed getting git password from secretKeyRef: %s", err.Error())
		return "", err
	}

	if password == "" {
		log.G(ctx).Debug("No git password in value or secretKeyRef fields")
	} else {
		log.G(ctx).Debug("Got git password from \"secretKeyRef\" field")
	}

	return password, nil
}

func getUserGitData(ctx context.Context, cfClient codefresh.Codefresh) (platmodel.GitProviders, string, error) {
	user, err := cfClient.V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return "", "", err
	}

	if user.ActiveAccount.GitProvider == nil {
		return "", "", fmt.Errorf("account \"%s\" is missing gitProvider data", *user.ActiveAccount.Name)
	}

	if user.ActiveAccount.GitAPIURL == nil {
		return "", "", fmt.Errorf("account \"%s\" is missing gitApiUrl data", *user.ActiveAccount.Name)
	}

	return *user.ActiveAccount.GitProvider, *user.ActiveAccount.GitAPIURL, nil
}

func getValueFromSecretKeyRef(ctx context.Context, opts *HelmValidateValuesOptions, secretKeyRef chartutil.Values) (string, error) {
	name, err := helm.PathValue[string](secretKeyRef, "name")
	if err != nil {
		return "", errors.New("\"secretKeyRef.name\" must be a non-empty string")
	}

	key, err := helm.PathValue[string](secretKeyRef, "key")
	if err != nil {
		return "", errors.New("\"secretKeyRef.key\" must be a non-empty string")
	}

	if name == "" && key == "" {
		return "", nil
	}

	return kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, name, key)
}
