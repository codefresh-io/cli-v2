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

package util

import (
	"context"
	"fmt"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	accountpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/account"
	clusterpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/cluster"
	v1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/util/localconfig"
	"k8s.io/client-go/tools/clientcmd"
)

type (
	CreateAppOptions struct {
		Name        string
		Namespace   string
		Project     string
		SyncWave    int
		RepoURL     string
		Revision    string
		SrcPath     string
		DestServer  string
		NoFinalizer bool
	}
)

// GenerateToken runs argocd command to generate an argo-cd access token
func GenerateToken(ctx context.Context, accountName, kubeContext, namespace string, insecure bool) (string, error) {
	argoClient, err := createArgoClient(kubeContext, namespace, insecure)
	if err != nil {
		return "", err
	}

	conn, accountIf, err := argoClient.NewAccountClient()
	if err != nil {
		return "", fmt.Errorf("failed to create argocd account client: %w", err)
	}
	defer conn.Close()

	res, err := accountIf.CreateToken(ctx, &accountpkg.CreateTokenRequest{
		Name: accountName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate account token: %w", err)
	}

	return res.Token, nil
}

func GetClusterList(ctx context.Context, kubeContext, namespace string, insecure bool) (*v1alpha1.ClusterList, error) {
	argoClient, err := createArgoClient(kubeContext, namespace, insecure)
	if err != nil {
		return nil, err
	}

	conn, clusterIf, err := argoClient.NewClusterClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create argocd cluster client: %w", err)
	}
	defer conn.Close()

	return clusterIf.List(ctx, &clusterpkg.ClusterQuery{})
}

func createArgoClient(kubeContext, namespace string, insecure bool) (apiclient.Client, error) {
	defaultLocalConfigPath, err := localconfig.DefaultLocalConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to load argocd config: %w", err)
	}

	return apiclient.NewClient(&apiclient.ClientOptions{
		Insecure:             insecure,
		ConfigPath:           defaultLocalConfigPath,
		PortForwardNamespace: namespace,
		KubeOverrides: &clientcmd.ConfigOverrides{
			CurrentContext: kubeContext,
		},
	})
}
