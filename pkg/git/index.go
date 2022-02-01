package git

func GetTokenVerifier(provider string) func(string)(bool, error) {
	if provider == "github" {
		return VerifyGitHubTokenScope
	}

	if provider == "gitlab" {
		return VerifyGitLabTokenScope
	}
	
	return nil
}