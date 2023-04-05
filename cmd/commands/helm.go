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
	"os"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/cli-v2/pkg/util/kube"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"

	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
)

type (
	Values struct {
		Global *Global `json:"global,omitempty"`
	}

	Global struct {
		Codefresh *Codefresh `json:"codefresh,omitempty"`
		Runtime   *Runtime   `json:"runtime,omitempty"`
	}

	Codefresh struct {
		Url            string          `json:"url,omitempty"`
		ApiEventsPath  string          `json:"apiEventsPath,omitempty"`
		AccountId      string          `json:"accountId,omitempty"`
		GitIntegration *GitIntegration `json:"gitIntegration,omitempty"`
		UserToken      *UserToken      `json:"userToken,omitempty"`
	}

	GitIntegration struct {
		Provider *struct {
			Bame   string `json:"name,omitempty"`
			ApiUrl string `json:"apiUrl,omitempty"`
		} `json:"provider,omitempty"`
	}

	UserToken struct {
		Token        string        `json:"token,omitempty"`
		SecretKeyRef *SecretKeyRef `json:"secretKeyRef,omitempty"`
	}

	Runtime struct {
		Name           string          `json:"name,omitempty"`
		Cluster        string          `json:"cluster,omitempty"`
		Ingress        *Ingress        `json:"ingress,omitempty"`
		GitCredentials *GitCredentials `json:"gitCredentials,omitempty"`
	}

	Ingress *struct {
		Enabled     bool      `json:"enabled,omitempty"`
		Protocol    Protocol  `json:"protocol,omitempty"`
		ClassName   string    `json:"className,omitempty"`
		Tls         *struct{} `json:"tls,omitempty"`
		Annotations *struct{} `json:"annotations,omitempty"`
		Hosts       []string  `json:"hosts,omitempty"`
	}

	Protocol string

	GitCredentials struct {
		Username string    `json:"username,omitempty"`
		Password *Password `json:"password,omitempty"`
	}

	Password struct {
		Value        string        `json:"value,omitempty"`
		SecretKeyRef *SecretKeyRef `json:"secretKeyRef,omitempty"`
	}

	SecretKeyRef struct {
		Name string `json:"name,omitempty"`
		Key  string `json:"key,omitempty"`
	}

	HelmValidateValuesOptions struct {
		helmFile    string
		namespace   string
		kubeFactory apkube.Factory
	}
)

const (
	// standard installation using an ingress resource
	ProtocolHttps Protocol = "https"
	// ingressless installation, using an FRP tunnel
	ProtocolHttp Protocol = "http"
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
				return fmt.Errorf("failed validating file \"%s\": %w", opts.helmFile, err)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.helmFile, "values", "v", "values.yaml", "The values file to validate")

	opts.kubeFactory = apkube.AddFlags(cmd.Flags())
	return cmd
}

func runHelmValidate(ctx context.Context, opts *HelmValidateValuesOptions) error {
	values, err := readValuesFile(opts.helmFile)
	if err != nil {
		return err
	}

	err = basicValuesCheck(values)
	if err != nil {
		return err
	}

	if opts.namespace == "" {
		opts.namespace = values.Global.Runtime.Name
	}

	cfClient, err := getPlatformClient(ctx, opts, values.Global.Codefresh)
	if err != nil {
		return err
	}

	err = checkUserPermission(ctx, cfClient)

	err = checkRuntimeName(ctx, cfClient, values.Global.Runtime)
	if err != nil {
		return err
	}

	return nil
}

func readValuesFile(helmFile string) (*Values, error) {
	valuesStr, err := os.ReadFile(helmFile)
	if err != nil {
		return nil, fmt.Errorf("failed reading file: %w", err)
	}

	values := &Values{}
	err = yaml.Unmarshal(valuesStr, values)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling file: %w", err)
	}

	return values, nil
}

func basicValuesCheck(values *Values) error {
	if values.Global == nil {
		return fmt.Errorf("missing \"global\" section in values file")
	}

	if values.Global.Codefresh == nil {
		return fmt.Errorf("missing \"global.codefresh\" section in values file")
	}

	if values.Global.Codefresh.UserToken == nil {
		return fmt.Errorf("missing \"global.codefresh.userToken\" section in values file")
	}

	if values.Global.Runtime == nil {
		return fmt.Errorf("missing \"global.runtime\" section in values file")
	}

	if values.Global.Runtime.Name == "" {
		return fmt.Errorf("missing \"global.runtime.name\" section in values file")
	}

	return nil
}

func getPlatformClient(ctx context.Context, opts *HelmValidateValuesOptions, cf *Codefresh) (codefresh.Codefresh, error) {
	userToken, err := getUserToken(ctx, opts, cf)
	if err != nil {
		return nil, err
	}

	return cfConfig.NewAdHocClient(ctx, cf.Url, userToken)
}

func getUserToken(ctx context.Context, opts *HelmValidateValuesOptions, cf *Codefresh) (string, error) {
	userToken := cf.UserToken
	if userToken == nil {
		return "", errors.New("missing userToken value")
	}

	if userToken.Token != "" {
		return userToken.Token, nil
	}

	if userToken.SecretKeyRef == nil {
		return "", errors.New("userToken must contain either a \"token\" field, or a \"secretKeyRef\"")
	}

	secretKeyRef := userToken.SecretKeyRef
	if secretKeyRef.Name == "" {
		return "", errors.New("userToken.secretKeyRef must include a \"name\" field")
	}

	if secretKeyRef.Key == "" {
		return "", errors.New("userToken.secretKeyRef must include a \"key\" field")
	}

	token, err := kube.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, secretKeyRef.Name, secretKeyRef.Key)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func checkUserPermission(ctx context.Context, cfClient codefresh.Codefresh) error {
	user, err := cfClient.V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return err
	}

	if user.IsAdmin == nil || !*user.IsAdmin {
		return fmt.Errorf("user \"%s\" does not have Admin role", user.Name)
	}

	return nil
}

func checkRuntimeName(ctx context.Context, cfClient codefresh.Codefresh, runtime *Runtime) error {
	_, err := cfClient.V2().Runtime().Get(ctx, runtime.Name)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil // runtime does not exist
		}

		return fmt.Errorf("failed to get runtime: %w", err)
	}

	return fmt.Errorf("runtime \"%s\" already exists", runtime.Name)
}
