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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getPlatformClient(t *testing.T) {
	type args struct {
		opts            *HelmValidateValuesOptions
		codefreshValues map[string]interface{}
	}
	tests := map[string]struct {
		args    args
		wantErr string
	}{
		// TODO: Add test cases.
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := getPlatformClient(context.Background(), tt.args.opts, tt.args.codefreshValues)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if got == nil {
				t.Errorf("getPlatformClient() = %v, want not nil", got)
			}
		})
	}
}
