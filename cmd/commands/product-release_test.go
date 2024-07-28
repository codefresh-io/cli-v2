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

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/promotion-orchestrator"
)

func Test_ToProductReleaseStatus(t *testing.T) {
	type args struct {
		stringStatusList string
	}
	tests := []struct {
		name    string
		args    args
		want    []platmodel.ProductReleaseStatus
		wantErr error
	}{
		{
			name: "should fail",
			args: args{
				stringStatusList: "pending,running",
			},
			want:    nil,
			wantErr: fmt.Errorf("invalid status: %s", "pending"),
		},
		{
			name: "should fail",
			args: args{
				stringStatusList: "running ,failed",
			},
			want:    nil,
			wantErr: fmt.Errorf("invalid argument status"),
		},
		{
			name: "should convert to release status",
			args: args{
				stringStatusList: "running,failed",
			},
			want: []platmodel.ProductReleaseStatus{
				platmodel.ProductReleaseStatusRunning,
				platmodel.ProductReleaseStatusFailed,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statues, err := toProductReleaseStatus(tt.args.stringStatusList)
			if err == nil && tt.wantErr != nil {
				t.Errorf("test should've fail with error message: %v didnt failed", tt.wantErr)
			} else if err != nil && tt.wantErr == nil {
				t.Errorf("test shouldnt fail with error message: %v", err)
			} else if err != nil && tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("test should've fail with error message: %v got %v", tt.wantErr, err)
			} else if !reflect.DeepEqual(tt.want, statues) {
				t.Errorf("ToProductReleaseStatus() = %v, want %v", statues, tt.want)
			}
		})
	}
}

func Test_TransformSlice(t *testing.T) {
	productReleasesMock, _ := getProductReleaseMock()
	expected, _ := getProductReleaseJsonStringMock()
	type args struct {
		slice map[string]any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{
		{
			name: "should get product releases",
			args: args{
				slice: productReleasesMock,
			},
			want:    expected,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slice, err := TransformSlice(tt.args.slice)
			resJSON, err := json.MarshalIndent(slice.Edges, "", "\t")
			if err == nil && tt.wantErr != nil {
				t.Errorf("test should've fail with error message: %v didnt failed", tt.wantErr)
			} else if err != nil && tt.wantErr == nil {
				t.Errorf("test shouldnt fail with error message: %v", err)
			} else if err != nil && tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("test should've fail with error message: %v got %v", tt.wantErr, err)
			} else if !compareJSON(string(resJSON), tt.want) {
				t.Errorf("TransformSlice() = %v, want %v", string(resJSON), tt.want)
			}
		})
	}
}

func Test_ToPromotionFlows(t *testing.T) {
	type args struct {
		promotionFlowsList string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "should fail",
			args: args{
				promotionFlowsList: "running ,failed",
			},
			want:    nil,
			wantErr: fmt.Errorf("invalid argument "),
		},
		{
			name: "should convert to prmotion flows",
			args: args{
				promotionFlowsList: "flow1,flow2",
			},
			want: []string{
				"flow1",
				"flow2",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statues, err := ToPromotionFlows(tt.args.promotionFlowsList)
			if err == nil && tt.wantErr != nil {
				t.Errorf("test should've fail with error message: %v didnt failed", tt.wantErr)
			} else if err != nil && tt.wantErr == nil {
				t.Errorf("test shouldnt fail with error message: %v", err)
			} else if err != nil && tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("test should've fail with error message: %v got %v", tt.wantErr, err)
			} else if !reflect.DeepEqual(tt.want, statues) {
				t.Errorf("ToProductReleaseStatus() = %v, want %v", statues, tt.want)
			}
		})
	}
}
func UnmarshelSlice(releaseSlice productReleaseSlice) (map[string]any, error) {
	data, err := json.MarshalIndent(releaseSlice, "", "\t")
	if err != nil {
		return nil, err
	}

	var releaseMap map[string]any
	err = json.Unmarshal(data, &releaseMap)
	if err != nil {
		return nil, err
	}
	return releaseMap, nil
}
func getProductReleaseMock() (map[string]any, error) {
	pageInfo := platmodel.SliceInfo{
		HasNextPage: true,
		HasPrevPage: false,
	}
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
		Edges: []*productReleaseEdge{
			&edge1,
			&edge2,
		},
		PageInfo: &pageInfo,
	}
	return UnmarshelSlice(slice)
}

func getProductReleaseJsonStringMock() (string, error) {
	file, err := os.Open("./product-release_mock.json")
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func compareJSON(expected, actual string) bool {
	var expectedData, actualData interface{}
	err := json.Unmarshal([]byte(expected), &expectedData)
	if err != nil {
		return false
	}
	err = json.Unmarshal([]byte(actual), &actualData)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(expectedData, actualData)
}
