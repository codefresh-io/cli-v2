package git

import "fmt"

func VerifyGitLabTokenScope(token string) (bool, error) {
	fmt.Print("Skipping token verification for gitlab")
	
	return true, nil
}