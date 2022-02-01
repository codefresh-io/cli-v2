package git

import "context"

func GetTokenVerifier(provider string) func(context.Context, string)(bool, error) {
	if provider == "github" {
		return VerifyGitHubTokenScope
	}

	if provider == "gitlab" {
		return VerifyGitLabTokenScope
	}

	return nil
}