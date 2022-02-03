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

package git

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/log"
)


var (
	requiredGitHubScopes = []string{ "repo", "admin:repo_hook" }
)


func VerifyToken(ctx context.Context, provider string, token string) error {
	providerToVerifier := map[string]func(context.Context, string)error {
		"github": verifyGitHubTokenScope,
	}

	verifier := providerToVerifier[provider]
	if verifier == nil {
		return verifyTokenScopeFallback(ctx, provider)
	}

	return verifier(ctx, token)
}

func verifyGitHubTokenScope(ctx context.Context, token string) error {
	errMessage := "the provided git token is missing one or more of the required scopes:" + strings.Join(requiredGitHubScopes, ", ")
	
	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://api.github.com/", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	rawScopes := resp.Header["X-Oauth-Scopes"]
	var scopes []string
	if len(rawScopes) > 0 {
		scopes = strings.Split(rawScopes[0], ", ")
	}

	for _, rs := range requiredGitHubScopes {
		var contained bool
		for _, scope := range scopes {
			if scope == rs {
				contained = true
				break
			}
		}

		if !contained {
			return fmt.Errorf(errMessage)
		}
	}

	return nil
}

func verifyTokenScopeFallback(ctx context.Context, token string) error {
	log.G(ctx).Info("Skipping token verification")

	return nil
}
