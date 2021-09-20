package aputil

import (
	"context"
	"errors"
	"io"

	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	aplog "github.com/argoproj-labs/argocd-autopilot/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	pushRetries = 3
)

type CloneFlagsOptions struct {
	Prefix           string
	Optional         bool
	CreateIfNotExist bool
	Progress         io.Writer
}

func AddCloneFlags(cmd *cobra.Command, o *CloneFlagsOptions) *git.CloneOptions {
	opts := git.AddFlags(cmd, &git.AddFlagsOptions{
		FS:               memfs.New(),
		Prefix:           o.Prefix,
		CreateIfNotExist: o.CreateIfNotExist,
		Optional:         o.Optional,
	})

	opts.Progress = o.Progress
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}

	return opts
}

func PushWithMessage(ctx context.Context, r git.Repository, msg string, progress ...io.Writer) error {
	var (
		err  error
		prog io.Writer
	)

	if len(progress) > 0 {
		prog = progress[0]
	}

	for try := 0; try < pushRetries; try++ {
		_, err = r.Persist(ctx, &git.PushOptions{
			AddGlobPattern: ".",
			CommitMsg:      msg,
			Progress:       prog,
		})
		if err == nil || !errors.Is(err, transport.ErrRepositoryNotFound) {
			break
		}

		log.G(ctx).WithFields(log.Fields{
			"retry": try,
			"err":   err.Error(),
		}).Debug("failed to push to repository")
	}

	return err
}

func ConfigureLoggerOrDie() {
	logger := aplog.FromLogrus(logrus.NewEntry(logrus.New()), &aplog.LogrusConfig{Level: "warn"})
	util.Die(logger.Configure())
	aplog.L = logger
}
