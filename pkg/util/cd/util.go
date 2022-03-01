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
	"time"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	accountpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/account"
	"github.com/argoproj/argo-cd/v2/util/localconfig"
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
func GenerateToken(ctx context.Context, namespace string, account string, expires *time.Duration, insecure bool) (string, error) {
	clientOpts := &apiclient.ClientOptions{
		PortForward:          true,
		PortForwardNamespace: namespace,
		PlainText:            insecure,
	}

	defaultLocalConfigPath, err := localconfig.DefaultLocalConfigPath()
	if err != nil {
		return "", fmt.Errorf("failed to load argocd config: %w", err)
	}

	clientOpts.ConfigPath = defaultLocalConfigPath

	argoClient, err := apiclient.NewClient(clientOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create argocd client: %w", err)
	}

	conn, accountIf, err := argoClient.NewAccountClient()
	if err != nil {
		return "", fmt.Errorf("failed to create argocd account client: %w", err)
	}
	defer conn.Close()

	opts := &accountpkg.CreateTokenRequest{}
	if expires != nil {
		opts.ExpiresIn = int64(expires.Seconds())
	}

	if account != "" {
		opts.Name = account
	}

	res, err := accountIf.CreateToken(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate account token: %w", err)
	}

	return res.Token, nil
}
