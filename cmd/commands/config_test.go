// Copyright 2023 The Codefresh Authors.
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

	cfgit "github.com/codefresh-io/cli-v2/pkg/git"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/stretchr/testify/assert"
)

func Test_updateCsdpSettingsPreRunHandler(t *testing.T) {
	store.Get().Silent = true
	tests := map[string]struct {
		opts            *updateCsdpSettingsOpts
		wantGitProvider cfgit.ProviderType
		wantGitApiUrl   string
		wantErr         string
	}{
		"should succeed when all values are available and matching": {
			opts: &updateCsdpSettingsOpts{
				gitProvider:      cfgit.GITHUB,
				gitApiUrl:        cfgit.GITHUB_CLOUD_API_URL,
				sharedConfigRepo: cfgit.GITHUB_CLOUD_BASE_URL + "org/repo.git",
			},
			wantGitProvider: cfgit.GITHUB,
			wantGitApiUrl:   cfgit.GITHUB_CLOUD_API_URL,
		},
		"should succeed when shared-config-repo has cloud values": {
			opts: &updateCsdpSettingsOpts{
				sharedConfigRepo: cfgit.GITHUB_CLOUD_BASE_URL + "org/repo.git",
			},
			wantGitProvider: cfgit.GITHUB,
			wantGitApiUrl:   cfgit.GITHUB_CLOUD_API_URL,
		},
		"should succeed when shared-config-repo is on-prem and all values are supplied": {
			opts: &updateCsdpSettingsOpts{
				gitProvider:      cfgit.GITHUB,
				gitApiUrl:        "https://some.ghe.server/api/v3",
				sharedConfigRepo: "https://some.ghe.server/org/repo.git",
			},
			wantGitProvider: cfgit.GITHUB,
			wantGitApiUrl:   "https://some.ghe.server/api/v3",
		},
		"should fail when user supplies wrong git-provider": {
			opts: &updateCsdpSettingsOpts{
				gitProvider:      cfgit.GITLAB,
				sharedConfigRepo: cfgit.GITHUB_CLOUD_BASE_URL + "org/repo.git",
			},
			wantErr: "supplied provider \"gitlab\" does not match inferred provider \"github\" for url \"https://github.com/\"",
		},
		"should fail when user supplies wrong git-api-url": {
			opts: &updateCsdpSettingsOpts{
				gitApiUrl:        "https://www.github.com/wrong/api",
				sharedConfigRepo: cfgit.GITHUB_CLOUD_BASE_URL + "org/repo.git",
			},
			wantErr: "supplied git-api-url \"https://www.github.com/wrong/api\" does not match inferred git-api-url \"https://api.github.com\" from shared-config-repo",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := updateCsdpSettingsPreRunHandler(tt.opts)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantGitProvider, tt.opts.gitProvider)
			assert.Equal(t, tt.wantGitApiUrl, tt.opts.gitApiUrl)
		})
	}
}
