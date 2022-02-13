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

type TokenTypes string

const (
	RuntimeToken TokenTypes = "runtime token"
	PersonalToken TokenTypes = "personal token"
)

var (
	requiredGitHubRuntimeScopes = []string{ "repo", "admin:repo_hook" }
	requiredGitHubGitSourceScopes = []string{ "repo" }
	
	typeToGitHubScopes = map[TokenTypes][]string {
		RuntimeToken: requiredGitHubRuntimeScopes,
		PersonalToken: requiredGitHubGitSourceScopes,
	}
)



func VerifyToken(ctx context.Context, provider string, token string, tokenType TokenTypes) error {
	providerToVerifier := map[string]func(context.Context, string, TokenTypes)error {
		"github": verifyGitHubTokenScope,
	}

	verifier := providerToVerifier[provider]
	if verifier == nil {
		return verifyTokenScopeFallback(ctx, provider)
	}

	return verifier(ctx, token, tokenType)
}

func verifyGitHubTokenScope(ctx context.Context, token string, tokenType TokenTypes) error {
	errMessage := fmt.Sprintf("the provided %s is missing one or more of the required scopes: %s", tokenType, strings.Join(typeToGitHubScopes[tokenType], ", "))
	
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

	for _, rs := range typeToGitHubScopes[tokenType] {
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

	log.G(ctx).Info("Token verified")

	return nil
}

func verifyTokenScopeFallback(ctx context.Context, token string) error {
	log.G(ctx).Info("Skipping token verification")

	return nil
}
