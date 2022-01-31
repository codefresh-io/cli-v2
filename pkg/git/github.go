package git

import (
	"fmt"
	"net/http"
	"strings"
)

func VerifyGitHubTokenScope(token string) (bool, error) {
	req, _ := http.NewRequest("HEAD", "https://api.github.com/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	scopes := strings.Split(resp.Header["X-Oauth-Scopes"][0], ", ")
	var repo bool
	var adminRepoHook bool

	for _, scope := range scopes {
		if scope == "repo" {
			repo = true
		}
		if scope == "admin:repo_hook" {
			adminRepoHook = true
		}
	}

	if repo && adminRepoHook {
		return true, nil
	}

	return false, nil
}