package git

import (
	"context"

	"github.com/codefresh-io/cli-v2/pkg/log"
)

func VerifyGitLabTokenScope(ctx context.Context, token string) (bool, error) {
	log.G(ctx).Info("Skipping token verification for gitlab")

	return true, nil
}