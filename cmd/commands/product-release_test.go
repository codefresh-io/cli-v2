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
			name: "should fail caused by invalid status - non-existent",
			args: args{
				statuses: []string{
					"running",
					"non-existent",
				},
			},
			want:    nil,
			wantErr: "invalid product release status: non-existent",
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
			name: "should convert to release status when separated with ,",
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
			name: "should extract node from ProductRelease",
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

func Test_ExtractNodesFromEdges_WithPromotions(t *testing.T) {
	type args struct {
		edges []productReleaseEdge
	}
	expected, err := getPromotionJsonStringMock()

	tests := []struct {
		name    string
		args    args
		want    []map[string]any
		wantErr string
	}{
		{
			name: "should extract node from Promotion",
			args: args{
				edges: getPromotionMock().Edges,
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

func Test_ExtractNodesFromEdges_Mixed(t *testing.T) {
	type args struct {
		edges []productReleaseEdge
	}
	productReleaseMock := getProductReleaseMock()
	promotionMock := getPromotionMock()

	// Create mixed edges
	mixedEdges := append(productReleaseMock.Edges, promotionMock.Edges...)

	tests := []struct {
		name    string
		args    args
		wantLen int
	}{
		{
			name: "should extract nodes from mixed ProductRelease and Promotion",
			args: args{
				edges: mixedEdges,
			},
			wantLen: len(productReleaseMock.Edges) + len(promotionMock.Edges),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := extractNodesFromEdges(tt.args.edges)
			assert.Equal(t, tt.wantLen, len(nodes))

			// Verify first node is ProductRelease type
			if len(nodes) > 0 {
				_, hasReleaseId := nodes[0]["releaseId"]
				assert.True(t, hasReleaseId, "First node should have releaseId (ProductRelease)")
			}

			// Verify last nodes are Promotion type
			if len(nodes) > len(productReleaseMock.Edges) {
				lastNode := nodes[len(nodes)-1]
				_, hasId := lastNode["id"]
				_, hasTypename := lastNode["__typename"]
				assert.True(t, hasId, "Last node should have id (Promotion)")
				assert.True(t, hasTypename, "Last node should have __typename (Promotion)")
			}
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

func getPromotionMock() productReleaseSlice {
	node1 := map[string]any{
		"__typename": "Promotion",
		"createdAt":  "2025-11-12T07:58:00.829Z",
		"environments": []map[string]interface{}{
			{
				"__typename": "PromotionEnvironment",
				"name":       "dev",
				"status":     "TERMINATED",
			},
			{
				"__typename": "PromotionEnvironment",
				"name":       "staging",
				"status":     "SKIPPED",
			},
		},
		"failure": map[string]interface{}{
			"message": "terminated by concurrency",
		},
		"id":                  "69143e08d3fc600692f605b6",
		"productName":         "my-product",
		"promotionAppVersion": "0.1.0",
		"promotionFlowName":   "test-post-trigger",
		"status":              "TERMINATED",
		"triggerCommitInfo": map[string]interface{}{
			"avatarURL":    "https://avatars.githubusercontent.com/u/88274488?v=4",
			"commitAuthor": "kim-codefresh <kim.aharfi@codefresh.io>",
			"commitSha":    "b03059b9defaaef46f7d3a817eb9449cf8d89730",
		},
	}
	edge1 := productReleaseEdge{
		Node: node1,
	}

	node2 := map[string]any{
		"__typename": "Promotion",
		"createdAt":  "2025-11-12T07:57:04.410Z",
		"environments": []map[string]interface{}{
			{
				"__typename": "PromotionEnvironment",
				"name":       "dev",
				"status":     "TERMINATED",
			},
			{
				"__typename": "PromotionEnvironment",
				"name":       "staging",
				"status":     "SKIPPED",
			},
		},
		"failure": map[string]interface{}{
			"message": "terminated by concurrency",
		},
		"id":                  "69143dd0d3fc600692f6056d",
		"productName":         "my-product",
		"promotionAppVersion": "0.1.0",
		"promotionFlowName":   "test-post-trigger",
		"status":              "TERMINATED",
		"triggerCommitInfo": map[string]interface{}{
			"avatarURL":    "https://avatars.githubusercontent.com/u/88274488?v=4",
			"commitAuthor": "kim-codefresh <kim.aharfi@codefresh.io>",
			"commitSha":    "b03059b9defaaef46f7d3a817eb9449cf8d89730",
		},
	}
	edge2 := productReleaseEdge{
		Node: node2,
	}

	node3 := map[string]any{
		"__typename": "Promotion",
		"createdAt":  "2025-11-11T11:37:10.675Z",
		"environments": []map[string]interface{}{
			{
				"__typename": "PromotionEnvironment",
				"name":       "dev",
				"status":     "SUCCEEDED",
			},
			{
				"__typename": "PromotionEnvironment",
				"name":       "staging",
				"status":     "SUCCEEDED",
			},
			{
				"__typename": "PromotionEnvironment",
				"name":       "production",
				"status":     "TERMINATED",
			},
		},
		"failure": map[string]interface{}{
			"message": "terminated by concurrency",
		},
		"id":                  "69131fe6f2ed885fcec97175",
		"productName":         "my-product",
		"promotionAppVersion": "0.1.0",
		"promotionFlowName":   "demo",
		"status":              "TERMINATED",
		"triggerCommitInfo": map[string]interface{}{
			"avatarURL":    "https://avatars.githubusercontent.com/u/88274488?v=4",
			"commitAuthor": "kim-codefresh <kim.aharfi@codefresh.io>",
			"commitSha":    "b03059b9defaaef46f7d3a817eb9449cf8d89730",
		},
	}
	edge3 := productReleaseEdge{
		Node: node3,
	}

	slice := productReleaseSlice{
		Edges: []productReleaseEdge{
			edge1,
			edge2,
			edge3,
		},
	}
	return slice
}

func getPromotionJsonStringMock() ([]map[string]any, error) {
	file, err := os.Open("./promotion_mock.json")
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

func Test_ToProductReleaseStatus_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr string
	}{
		{
			name:    "should fail with semicolon in status",
			input:   []string{"running; failed"},
			wantErr: "invalid product release status: running; failed",
		},
		{
			name:    "should fail with completely invalid status",
			input:   []string{"invalid-status"},
			wantErr: "invalid product release status: invalid-status",
		},
		{
			name:    "should fail with empty status string",
			input:   []string{""},
			wantErr: "invalid product release status: ",
		},
		{
			name:    "should fail with mixed valid and invalid",
			input:   []string{"RUNNING", "INVALID", "FAILED"},
			wantErr: "invalid product release status: INVALID",
		},
		{
			name:    "should fail with numeric status",
			input:   []string{"123"},
			wantErr: "invalid product release status: 123",
		},
		{
			name:    "should fail with special characters",
			input:   []string{"RUNNING@#$"},
			wantErr: "invalid product release status: RUNNING@#$",
		},
		{
			name:    "should fail with SQL injection attempt",
			input:   []string{"RUNNING' OR '1'='1"},
			wantErr: "invalid product release status: RUNNING' OR '1'='1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := toProductReleaseStatus(tt.input)
			assert.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func Test_ToProductReleaseStatus_SuccessCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []platmodel.ProductReleaseStatus
	}{
		{
			name:  "should handle lowercase statuses",
			input: []string{"running", "failed", "succeeded"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
				platmodel.ProductReleaseStatusSucceeded,
			},
		},
		{
			name:  "should handle uppercase statuses",
			input: []string{"RUNNING", "FAILED", "SUCCEEDED"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
				platmodel.ProductReleaseStatusSucceeded,
			},
		},
		{
			name:  "should handle mixed case statuses",
			input: []string{"RuNnInG", "FaIlEd", "SuCcEeDeD"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
				platmodel.ProductReleaseStatusSucceeded,
			},
		},
		{
			name:  "should trim whitespace",
			input: []string{"  RUNNING  ", "FAILED   ", "   SUCCEEDED"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
				platmodel.ProductReleaseStatusSucceeded,
			},
		},
		{
			name:     "should handle empty array",
			input:    []string{},
			expected: nil,
		},
		{
			name:  "should handle single status",
			input: []string{"RUNNING"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
			},
		},
		{
			name:  "should handle suspended status",
			input: []string{"SUSPENDED"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusSuspended,
			},
		},
		{
			name:  "should handle terminated status",
			input: []string{"TERMINATED"},
			expected: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusTerminated,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := toProductReleaseStatus(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
