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

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
)

func Test_getSuffixToClusterName(t *testing.T) {
	cluster1 := getEmptyClusterEntity()
	cluster2 := getEmptyClusterEntity()
	cluster3 := getEmptyClusterEntity()

	cluster1.Metadata.Name = "test-cluster"
	cluster2.Metadata.Name = "test-cluster-1"
	cluster3.Metadata.Name = "test-cluster-2"

	clusters := []platmodel.Cluster{
		cluster1,
		cluster2,
		cluster3,
	}

	type args struct {
		clusters []platmodel.Cluster
		name     string
		tempName string
		counter  int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "should return 3",
			args: args{
				clusters: clusters,
				name:     "test-cluster",
				tempName: "test-cluster",
				counter:  0,
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSuffixToClusterName(tt.args.clusters, tt.args.name, tt.args.tempName, tt.args.counter); got != tt.want {
				t.Errorf("getSuffixToClusterName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_sanitizeClusterName(t *testing.T) {
	tests := map[string]struct {
		name    string
		want    string
		wantErr bool
	}{
		"should return sanitized string": {
			name:    "^-.123test!@-:cluster&*`;')test.cluster(-12_3=+::±§.",
			want:    "test----cluster------test-cluster--12-3",
			wantErr: false,
		},
		"should return error of sanitization failed": {
			name:    "12345",
			want:    "",
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := sanitizeClusterName(tt.name)

			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeClusterName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("sanitizeClusterName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateClusterName(t *testing.T) {
	tests := map[string]struct {
		name    string
		wantErr bool
	}{
		"name should be valid": {
			name:    "test-cluster-123",
			wantErr: false,
		},
		"name should not be valid (contains uppercase)": {
			name:    "Test-cluster",
			wantErr: true,
		},
		"name should not be valid (contains invalid chars)": {
			name:    "test-cluster:test/cluster.123#",
			wantErr: true,
		},
		"name should not be valid (begins with numeric char)": {
			name:    "2test-cluster",
			wantErr: true,
		},
		"name should not be valid (too long)": {
			name:    "this-cluster-name-is-too-long-1-this-cluster-name-is-too-long-1-this-cluster-name-is-too-long-1-123",
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateClusterName(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("validateClusterName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func getEmptyClusterEntity() platmodel.Cluster {
	empty := ""
	return platmodel.Cluster{
		Metadata: &platmodel.ObjectMeta{
			Group:       "",
			Version:     "",
			Kind:        "",
			Name:        "",
			Description: &empty,
			Namespace:   &empty,
			Runtime:     "",
			Cluster:     &empty,
			Account:     "",
			Labels:      nil,
			Annotations: nil,
			LastUpdated: &empty,
			Created:     &empty,
			UID:         &empty,
		},
		Errors:       []platmodel.Error{},
		ReferencedBy: []platmodel.BaseEntity{},
		References:   []platmodel.BaseEntity{},
		Server:       "",
		Namespaces:   []string{},
	}
}
