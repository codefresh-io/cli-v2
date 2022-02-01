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
	providerToVerifier := map[string]func(context.Context, string)(bool, error) {
		"github": verifyGitHubTokenScope,
		"gitlab": verifyGitLabTokenScope,
	}

	verifier := providerToVerifier[provider]

	return verifier(ctx, token)
}

func verifyGitHubTokenScope(ctx context.Context, token string) (bool, error) {
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

	for _, rs := range requiredGitHubScopes {
		var contained bool
		for _, scope := range scopes {
			if scope == rs {
				contained = true
				break
			}
		}

		if !contained {
			return false, nil
		}
	}

	return true, nil
}

func verifyGitLabTokenScope(ctx context.Context, token string) (bool, error) {
	log.G(ctx).Info("Skipping token verification for gitlab")

	return true, nil
}
