package github

import (
	"context"
	"fmt"

	"github.com/google/go-github/v29/github"
	"golang.org/x/oauth2"
)

func isTokenWithAdminScope() bool {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: "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"},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	auth := client.Authorizations
	fmt.Print(auth)
	// list all repositories for the authenticated user
	//repos, _, err := client.Repositories.List(ctx, "", nil)

	return false
}