package commands

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
)

// ---- Mock types ----

type MockPaymentsClient struct {
	mock.Mock
}

func (m *MockPaymentsClient) GetLimitsStatus(ctx context.Context) (*platmodel.LimitsStatus, error) {
	args := m.Called(ctx)
	return args.Get(0).(*platmodel.LimitsStatus), args.Error(1)
}

// ---- Tests ----

func TestRunValidateLimits_Success(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limitClusters := 10
	usageClusters := 5
	limits := &platmodel.LimitsStatus{
		Status: true,
		Limits: &platmodel.GitOpsLimits{Clusters: &limitClusters},
		Usage:  &platmodel.GitOpsUsage{Clusters: &usageClusters},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{hook: false}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_ErrorFromClient(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	mockClient.On("GetLimitsStatus", ctx).Return(&platmodel.LimitsStatus{}, errors.New("backend error"))

	opts := ValidateLimitsOptions{}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "backend error")
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_LimitsExceeded(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limitClusters := 10
	usageClusters := 12
	limits := &platmodel.LimitsStatus{
		Status: false,
		Limits: &platmodel.GitOpsLimits{Clusters: &limitClusters},
		Usage:  &platmodel.GitOpsUsage{Clusters: &usageClusters},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{}
	err := runValidateLimits(ctx, &opts, mockClient)

	expected, _ := json.MarshalIndent(limits, "", "  ")
	assert.EqualError(t, err, "account limits exceeded for account: "+string(expected))
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_HookClusterLimitMatch(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limitClusters := 5
	usageClusters := 5
	limits := &platmodel.LimitsStatus{
		Status: true,
		Limits: &platmodel.GitOpsLimits{Clusters: &limitClusters},
		Usage:  &platmodel.GitOpsUsage{Clusters: &usageClusters},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{hook: true}
	err := runValidateLimits(ctx, &opts, mockClient)

	// Status should be set to false by hook condition
	limits.Status = false
	expected, _ := json.MarshalIndent(limits, "", "  ")
	assert.EqualError(t, err, "account limits (clusters) exceeded for account: "+string(expected))
	mockClient.AssertExpectations(t)
}
