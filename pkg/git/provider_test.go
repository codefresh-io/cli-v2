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

package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProvider(t *testing.T) {
	tests := map[string]struct {
		providerType ProviderType
		baseURL      string
		wantType     ProviderType
		wantApiURL   string
		wantErr      string
	}{
		"should return github when url is in github.com": {
			baseURL:    "https://github.com/org/repo",
			wantType:   GITHUB,
			wantApiURL: "https://api.github.com",
		},
		"should return gitlab when url is in gitlab.com": {
			baseURL:    "https://gitlab.com/org/repo",
			wantType:   GITLAB,
			wantApiURL: "https://gitlab.com/api/v4",
		},
		"should return bitbucket when url is in bitbucket.org": {
			baseURL:    "https://bitbucket.org/org/repo",
			wantType:   BITBUCKET,
			wantApiURL: "https://bitbucket.org/api/2.0",
		},
		"should use providedType when domain doesn't match known cloud providers": {
			providerType: BITBUCKET_SERVER,
			baseURL:      "https://some.on-prem-provider.com/org/repo",
			wantType:     BITBUCKET_SERVER,
			wantApiURL:   "https://some.on-prem-provider.com/org/repo",
		},
		"should fail if provider does not match known cloud url, and no providerType was supplied": {
			providerType: GITLAB,
			baseURL:      "https://github.com/org/repo",
			wantErr:      "supplied provider \"gitlab\" does not match inferred cloud provider \"github\" for url \"https://github.com/org/repo\"",
		},
		"should fail if using bitbucket with an on-prem url": {
			providerType: BITBUCKET,
			baseURL:      "https://some.on-prem-provider.com",
			wantErr:      "wrong domain for bitbucket provider: \"https://some.on-prem-provider.com\", expected \"bitbucket.org\"\n  maybe you meant to use \"bitbucket-server\" for on-prem git provider?",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetProvider(tt.providerType, tt.baseURL, "")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantType, got.Type())
			assert.Equal(t, tt.wantApiURL, got.ApiURL())
		})
	}
}
