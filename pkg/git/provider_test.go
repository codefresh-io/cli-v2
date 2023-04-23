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

package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProvider(t *testing.T) {
	tests := map[string]struct {
		providerType ProviderType
		baseUrl      string
		wantType     ProviderType
		wantApiUrl   string
		wantErr      string
	}{
		"should return github when url is in github.com": {
			baseUrl:    "https://github.com/org/repo",
			wantType:   GITHUB,
			wantApiUrl: "https://api.github.com",
		},
		"should return github when url is in www.github.com": {
			baseUrl:    "https://www.github.com/org/repo",
			wantType:   GITHUB,
			wantApiUrl: "https://api.github.com",
		},
		"should return gitlab when url is in gitlab.com": {
			baseUrl:    "https://gitlab.com/org/repo",
			wantType:   GITLAB,
			wantApiUrl: "https://gitlab.com/api/v4",
		},
		"should return bitbucket when url is in bitbucket.org": {
			baseUrl:    "https://bitbucket.org/org/repo",
			wantType:   BITBUCKET,
			wantApiUrl: "https://bitbucket.org/api/2.0",
		},
		"should use providedType when domain doesn't match known cloud providers": {
			providerType: BITBUCKET_SERVER,
			baseUrl:      "https://some.on-prem-provider.com/org/repo",
			wantType:     BITBUCKET_SERVER,
			wantApiUrl:   "https://some.on-prem-provider.com/rest/api/1.0",
		},
		"should fail if provider does not match known cloud url, and no providerType was supplied": {
			providerType: GITLAB,
			baseUrl:      "https://github.com/org/repo",
			wantErr:      "supplied provider \"gitlab\" does not match inferred provider \"github\" for url \"https://github.com/org/repo\"",
		},
		"should fail if using bitbucket with an on-prem url": {
			providerType: BITBUCKET,
			baseUrl:      "https://some.on-prem-provider.com/org/repo",
			wantErr:      "wrong baseURL for bitbucket provider: \"https://some.on-prem-provider.com/\", expected \"bitbucket.org\"\n  maybe you meant to use \"bitbucket-server\" for on-prem git provider?",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetProvider(tt.providerType, tt.baseUrl, "")
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.wantType, got.Type())
			assert.Equal(t, tt.wantApiUrl, got.ApiURL())
		})
	}
}
