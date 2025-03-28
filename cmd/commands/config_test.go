// Copyright 2025 The Codefresh Authors.
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

package commands

import (
	"testing"

	"github.com/codefresh-io/cli-v2/internal/git"
	"github.com/codefresh-io/cli-v2/internal/store"

	"github.com/stretchr/testify/assert"
)

func Test_updateCsdpSettingsPreRunHandler(t *testing.T) {
	store.Get().Silent = true
	tests := map[string]struct {
		opts            *updateGitOpsSettingsOpts
		wantGitProvider git.ProviderType
		wantGitApiURL   string
		wantInferred    bool
		wantErr         string
	}{
		"should succeed when all values are available and matching": {
			opts: &updateGitOpsSettingsOpts{
				gitProvider:      git.GITHUB,
				gitApiURL:        "https://api.github.com",
				sharedConfigRepo: "https://github.com/org/repo.git",
			},
			wantGitProvider: git.GITHUB,
			wantGitApiURL:   "https://api.github.com",
			wantInferred:    false,
		},
		"should succeed when shared-config-repo has cloud values": {
			opts: &updateGitOpsSettingsOpts{
				sharedConfigRepo: "https://github.com/org/repo.git",
			},
			wantGitProvider: git.GITHUB,
			wantGitApiURL:   "https://api.github.com",
			wantInferred:    true,
		},
		"should succeed when shared-config-repo is on-prem and all values are supplied": {
			opts: &updateGitOpsSettingsOpts{
				gitProvider:      git.GITHUB,
				gitApiURL:        "https://some.ghe.server/api/v3",
				sharedConfigRepo: "https://some.ghe.server/org/repo.git",
			},
			wantGitProvider: git.GITHUB,
			wantGitApiURL:   "https://some.ghe.server/api/v3",
			wantInferred:    false,
		},
		"should fail when user supplies wrong git-provider": {
			opts: &updateGitOpsSettingsOpts{
				gitProvider:      git.GITLAB,
				sharedConfigRepo: "https://github.com/org/repo.git",
			},
			wantErr: "supplied provider \"gitlab\" does not match inferred cloud provider \"github\" for url \"https://github.com/org/repo.git\"",
		},
		"should fail when user supplies wrong git-api-url on cloud provider": {
			opts: &updateGitOpsSettingsOpts{
				gitApiURL:        "https://github.com/wrong/api",
				sharedConfigRepo: "https://github.com/org/repo.git",
			},
			wantErr: "supplied git-api-url \"https://github.com/wrong/api\" does not match inferred git-api-url \"https://api.github.com\" from github cloud",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := updateGitOpsSettingsPreRunHandler(tt.opts)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantGitProvider, tt.opts.gitProvider)
			assert.Equal(t, tt.wantGitApiURL, tt.opts.gitApiURL)
		})
	}
}
