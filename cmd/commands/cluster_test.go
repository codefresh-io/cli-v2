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

package commands

import (
	"testing"

	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"
)

func Test_getSuffixToClusterName(t *testing.T) {
	cluster1 := getEmptyClusterEntity()
	cluster2 := getEmptyClusterEntity()
	cluster3 := getEmptyClusterEntity()
	
	cluster1.Metadata.Name = "test-cluster"
	cluster2.Metadata.Name = "test-cluster-1"
	cluster3.Metadata.Name = "test-cluster-2"

	clusters := []model.Cluster{
		cluster1,
		cluster2,
		cluster3,
	}

	type args struct {
		clusters []model.Cluster
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
				name: "test-cluster",
				tempName: "test-cluster",
				counter: 0,
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

func getEmptyClusterEntity() model.Cluster {
	empty := ""
	return model.Cluster{
		Metadata: &model.ObjectMeta{
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
		Errors:       []model.Error{},
		ReferencedBy: []model.BaseEntity{},
		References:   []model.BaseEntity{},
		Server:       "",
		Namespaces:   []string{},
	}
}
