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
	"fmt"
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
			statues, err := ToProductReleaseStatus(tt.args.stringStatusList)
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

func getProductReleaseMock() platmodel.ProductReleaseSlice {
	commiter := "kim-codefresh <kim.aharfi@codefresh.io>"
	promotionFlows := []string{"flow1", "flow2"}
	triggerEnv := "my-env"
	pageInfo := platmodel.SliceInfo{
		HasNextPage: true,
		HasPrevPage: false,
	}
	node1 := platmodel.ProductRelease{
		ReleaseID:          "669fac7668fc487b38c2ad19",
		ReleaseName:        "669fac7",
		PromotionFlowName:  &promotionFlows[0],
		TriggerEnvironment: &triggerEnv,
		Steps: []*platmodel.ProductReleaseStep{
			{
				EnvironmentName: "my-env",
				Status:          platmodel.ProductReleaseStepStatusSucceeded,
				DependsOn:       []string{},
				EnvironmentKind: platmodel.EnvironmentKindNonProd,
				Issues:          []platmodel.Issue{},
			},
			{
				EnvironmentName: "staging",
				Status:          platmodel.ProductReleaseStepStatusSucceeded,
				DependsOn: []string{
					"my-env",
				},
				EnvironmentKind: platmodel.EnvironmentKindNonProd,
				Issues:          []platmodel.Issue{},
			},
			{
				EnvironmentName: "prod",
				Status:          platmodel.ProductReleaseStepStatusFailed,
				DependsOn: []string{
					"staging",
				},
				EnvironmentKind: platmodel.EnvironmentKindProd,
				Issues:          []platmodel.Issue{},
			},
		},
		TriggerCommit: &platmodel.CommitInfo{
			Committer: &commiter,
		},
		Status:    platmodel.ProductReleaseStatusFailed,
		UpdatedAt: "2024-07-25T12:34:56Z",
		CreatedAt: "2024-07-24T12:34:56Z",
		Error:     nil,
	}
	edge1 := platmodel.ProductReleaseEdge{
		Node: &node1,
	}

	node2 := platmodel.ProductRelease{
		ReleaseID:          "669fac7668fc487b38c2ad19",
		ReleaseName:        "669fac7",
		PromotionFlowName:  &promotionFlows[0],
		TriggerEnvironment: &triggerEnv,
		Steps: []*platmodel.ProductReleaseStep{
			{
				EnvironmentName: "my-env",
				Status:          platmodel.ProductReleaseStepStatusSucceeded,
				DependsOn:       []string{},
				EnvironmentKind: platmodel.EnvironmentKindNonProd,
				Issues:          []platmodel.Issue{},
			},
			{
				EnvironmentName: "staging",
				Status:          platmodel.ProductReleaseStepStatusSucceeded,
				DependsOn: []string{
					"my-env",
				},
				EnvironmentKind: platmodel.EnvironmentKindNonProd,
				Issues:          []platmodel.Issue{},
			},
			{
				EnvironmentName: "prod",
				Status:          platmodel.ProductReleaseStepStatusFailed,
				DependsOn: []string{
					"staging",
				},
				EnvironmentKind: platmodel.EnvironmentKindProd,
				Issues:          []platmodel.Issue{},
			},
		},
		TriggerCommit: &platmodel.CommitInfo{
			Committer: &commiter,
		},
		Status:    platmodel.ProductReleaseStatusFailed,
		UpdatedAt: "2024-07-25T12:34:56Z",
		CreatedAt: "2024-07-24T12:34:56Z",
		Error:     nil,
	}
	edge2 := platmodel.ProductReleaseEdge{
		Node: &node2,
	}
	return platmodel.ProductReleaseSlice{
		Edges: []*platmodel.ProductReleaseEdge{
			&edge1,
			&edge2,
		},
		PageInfo: &pageInfo,
	}
}
