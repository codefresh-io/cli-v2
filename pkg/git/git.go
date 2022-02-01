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


func VerifyToken(ctx context.Context, provider string, token string) (bool, error) {
	providerToVerifier := map[string]func(context.Context, string)(bool, error){}

	providerToVerifier["github"] = VerifyGitHubTokenScope
	providerToVerifier["gitlab"] = VerifyGitLabTokenScope

	verifier := providerToVerifier[provider]

	return verifier(ctx, token)
}

func VerifyGitHubTokenScope(ctx context.Context, token string) (bool, error) {
	log.G(ctx).Info("Verifing your git token")

	req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://api.github.com/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	rawScopes := resp.Header["X-Oauth-Scopes"]
	var scopes []string
	if len(rawScopes) > 0 {
		scopes = strings.Split(rawScopes[0], ", ")
	}
	var repo bool
	var adminRepoHook bool

	for _, scope := range scopes {
		if scope == requiredGitHubScopes[0] {
			repo = true
		}
		if scope == requiredGitHubScopes[1] {
			adminRepoHook = true
		}
	}

	if repo && adminRepoHook {
		return true, nil
	}

	return false, nil
}

func VerifyGitLabTokenScope(ctx context.Context, token string) (bool, error) {
	log.G(ctx).Info("Skipping token verification for gitlab")

	return true, nil
}
