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

	apkube "github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/spf13/cobra"
)

const (
	// standard installation using an ingress resource
	ProtocolHttps Protocol = "https"
	// ingressless installation, using an FRP tunnel
	ProtocolHttp Protocol = "http"
)

type (
	SecretKeyRef struct {
		Name string `json:"name,omitempty"`
		Key  string `json:"key,omitempty"`
	}

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

	HelmValidateValuesOptions struct {
		helmFile    string
		kubeFactory apkube.Factory
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHelmValidate(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.helmFile, "values", "v", "values.yaml", "The values file to validate")

	opts.kubeFactory = apkube.AddFlags(cmd.Flags())
	return cmd
}

func runHelmValidate(_ context.Context, opts *HelmValidateValuesOptions) error {
	valuesStr, err := os.ReadFile(opts.helmFile)
	if err != nil {
		return fmt.Errorf("failed reading values file '%s': %w", opts.helmFile, err)
	}

	values := &Values{}
	err = yaml.Unmarshal(valuesStr, values)
	if err != nil {
		return fmt.Errorf("failed unmarshaling values file '%s': %w", opts.helmFile, err)
	}

	return nil
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
		return "", errors.New("userToken must contain ")
	}

	secretKeyRef := userToken.SecretKeyRef
	cs := opts.kubeFactory.KubernetesClientSetOrDie()
	secret, err :=cs.CoreV1().Secrets("").Get(ctx, secretKeyRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed reading userToken secretKeyRef %s: %w", secretKeyRef.Name, err)
	}

	value := secret.Data[secretKeyRef.Key]
	return string(value), nil
}
