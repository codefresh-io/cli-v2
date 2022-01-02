// Copyright 2022 The Codefresh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright 2021 The Codefresh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aputil

import (
	"context"
	"errors"
	"io"
	"time"

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
		}).Warn("Failed to push to repository, trying again in 3 seconds...")

		time.Sleep(time.Second * 3)
	}

	return err
}

func ConfigureLoggerOrDie(cmd *cobra.Command) {
	lvl := "warn"

	cobra.OnInitialize(func() {
		lvlFlag := cmd.Flags().Lookup("log-level")
		if lvlFlag != nil && lvlFlag.Value.String() == "debug" {
			lvl = "debug"
		}

		logger := aplog.FromLogrus(logrus.NewEntry(logrus.New()), &aplog.LogrusConfig{Level: lvl})
		util.Die(logger.Configure(), "failed to configure autopilot logger")
		aplog.L = logger
	})

	logger := aplog.FromLogrus(logrus.NewEntry(logrus.New()), &aplog.LogrusConfig{Level: lvl})
	util.Die(logger.Configure())
	aplog.L = logger
}
