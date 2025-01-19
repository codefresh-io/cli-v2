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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/promotion-orchestrator"
	"github.com/stretchr/testify/assert"
)

type ProductReleaseJson struct {
	ReleaseId string `json:"releaseId"`
	Status    string `json:"status"`
	Steps     []struct {
		EnvironmentName string `json:"environmentName"`
		Status          string `json:"status"`
	} `json:"steps"`
}

func Test_ToProductReleaseStatus(t *testing.T) {
	type args struct {
		statuses []string
	}
	tests := []struct {
		name    string
		args    args
		want    []platmodel.ProductReleaseStatus
		wantErr string
	}{
		{
			name: "should fail when status include ;",
			args: args{
				statuses: []string{
					"running; failed",
				},
			},
			want:    nil,
			wantErr: "invalid product release status: running; failed",
		},
		{
			name: "should fail caused by invalid status - pending",
			args: args{
				statuses: []string{
					"running",
					"pending",
				},
			},
			want:    nil,
			wantErr: "invalid product release status: pending",
		},
		{
			name: "should convert to release status when seperated by , with lower cases",
			args: args{
				statuses: []string{
					"running",
					"failed",
				},
			},
			want: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
			},
			wantErr: "",
		},
		{
			name: "should convert to release status when including spaces",
			args: args{
				statuses: []string{
					"RUNNING ",
					"SUCCEEDED",
				},
			},
			want: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusSucceeded,
			},
			wantErr: "",
		},
		{
			name: "should convert to release status when separted with ,",
			args: args{
				statuses: []string{
					"RUNNING",
					"FAILED",
				},
			},
			want: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statues, err := toProductReleaseStatus(tt.args.statuses)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			assert.ElementsMatch(t, tt.want, statues)
		})
	}
}

func Test_ExtractNodesFromEdges(t *testing.T) {
	type args struct {
		edges []productReleaseEdge
	}
	expected, err := getProductReleaseJsonStringMock()

	tests := []struct {
		name    string
		args    args
		want    []map[string]any
		wantErr string
	}{
		{
			name: "should extract node",
			args: args{
				edges: getProductReleaseMock().Edges,
			},
			want:    expected,
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := extractNodesFromEdges(tt.args.edges)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			stringNodes := fmt.Sprintf("%v", nodes)
			stringWant := fmt.Sprintf("%v", tt.want)
			assert.Equal(t, stringNodes, stringWant)
		})
	}
}

func getProductReleaseMock() productReleaseSlice {
	node1 := map[string]any{
		"releaseId": "669fac7668fc487b38c2ad19",
		"steps": []map[string]interface{}{
			{
				"environmentName": "my-env",
				"status":          platmodel.ProductReleaseStepStatusSucceeded,
			},
			{
				"environmentName": "staging",
				"status":          platmodel.ProductReleaseStepStatusSucceeded,
			},
			{
				"environmentName": "prod",
				"status":          platmodel.ProductReleaseStepStatusFailed,
			},
		},
		"status": platmodel.ProductReleaseStatusFailed,
	}
	edge1 := productReleaseEdge{
		Node: node1,
	}

	node2 := map[string]any{
		"releaseId": "669fac7668fc487b38c2ad18",
		"steps": []map[string]interface{}{
			{
				"environmentName": "my-env",
				"status":          platmodel.ProductReleaseStepStatusSucceeded,
			},
			{
				"environmentName": "staging",
				"status":          platmodel.ProductReleaseStepStatusSucceeded,
			},
			{
				"environmentName": "prod",
				"status":          platmodel.ProductReleaseStepStatusFailed,
			},
		},
		"status": platmodel.ProductReleaseStatusFailed,
	}
	edge2 := productReleaseEdge{
		Node: node2,
	}
	slice := productReleaseSlice{
		Edges: []productReleaseEdge{
			edge1,
			edge2,
		},
	}
	return slice
}

func getProductReleaseJsonStringMock() ([]map[string]any, error) {
	file, err := os.Open("./product-release_mock.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
