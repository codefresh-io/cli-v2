// Copyright 2024 The Codefresh Authors.
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
	"io"

	"github.com/codefresh-io/cli-v2/internal/util"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	aplog "github.com/argoproj-labs/argocd-autopilot/pkg/log"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type CloneFlagsOptions struct {
	Prefix           string
	Optional         bool
	CreateIfNotExist bool
	CloneForWrite    bool
	Progress         io.Writer
}

func AddCloneFlags(cmd *cobra.Command, opts *CloneFlagsOptions) *apgit.CloneOptions {
	co := apgit.AddFlags(cmd, &apgit.AddFlagsOptions{
		FS:               memfs.New(),
		Prefix:           opts.Prefix,
		CreateIfNotExist: opts.CreateIfNotExist,
		CloneForWrite:    opts.CloneForWrite,
		Optional:         opts.Optional,
	})

	co.Progress = opts.Progress
	if co.Progress == nil {
		co.Progress = io.Discard
	}

	return co
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

func AddRepoFlags(cmd *cobra.Command, opts *CloneFlagsOptions) *apgit.CloneOptions {
	co := AddCloneFlags(cmd, opts)
	util.Die(cmd.PersistentFlags().MarkHidden(opts.Prefix + "repo"))
	util.Die(cmd.PersistentFlags().MarkHidden(opts.Prefix + "upsert-branch"))
	util.Die(cmd.PersistentFlags().SetAnnotation(opts.Prefix+"repo", cobra.BashCompOneRequiredFlag, []string{"false"}))
	return co
}
