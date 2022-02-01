package git

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
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
	errMessage := "The provided git token is missing one or more of the required scopes:" + util.StringifyArray(requiredGitHubScopes)
	
	req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://api.github.com/", nil)
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
