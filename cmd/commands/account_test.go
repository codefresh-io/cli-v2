package commands

import (
	"context"
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

func ptr(i int) *int { return &i }

// ---- Tests ----

func TestRunValidateLimits_Success(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Clusters: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Clusters: ptr(5), Applications: ptr(10)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "reached"}
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

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Clusters: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Clusters: ptr(12), Applications: ptr(10)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: clusters limit exceeded: usage=12, limit=10")
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_ClusterLimitReached(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Clusters: ptr(5)},
		Usage:  &platmodel.GitOpsUsage{Clusters: ptr(5), Applications: ptr(5)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "reached", subject: "clusters"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: clusters limit reached: usage=5, limit=5")
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_UsageMissing(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Clusters: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Applications: ptr(5)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "reached", subject: "clusters"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: clusters usage is missing")
	mockClient.AssertExpectations(t)
}

func TestRunValidateLimits_ExceededPassesOnEqual(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Applications: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Applications: ptr(10)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded", subject: "applications"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.NoError(t, err)
}

func TestRunValidateLimits_SubjectApplicationsOnly(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{
			Applications: ptr(10),
			Clusters:     ptr(20),
		},
		Usage: &platmodel.GitOpsUsage{
			Applications: ptr(15),
			Clusters:     ptr(25), // will be ignored
		},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded", subject: "applications"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: applications limit exceeded: usage=15, limit=10")
}

func TestRunValidateLimits_InvalidFailCondition(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Applications: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Applications: ptr(10)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "oops", subject: "applications"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: invalid fail condition")
}

func TestRunValidateLimits_NoLimitsSet(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{
			Applications: nil,
			Clusters:     nil,
		},
		Usage: &platmodel.GitOpsUsage{
			Applications: ptr(7),
			Clusters:     ptr(7),
		},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded", subject: ""}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.NoError(t, err)
}

func TestRunValidateLimits_ReachedFailsOnEqual(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{Clusters: ptr(10)},
		Usage:  &platmodel.GitOpsUsage{Clusters: ptr(10)},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "reached", subject: "clusters"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: clusters limit reached: usage=10, limit=10")
}

func TestRunValidateLimits_SubjectIgnoredClustersExceeded(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{
			Applications: ptr(10),
			Clusters:     ptr(20),
		},
		Usage: &platmodel.GitOpsUsage{
			Applications: ptr(5),
			Clusters:     ptr(25), // exceeded, but should be ignored
		},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded", subject: "applications"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.NoError(t, err)
}

func TestRunValidateLimits_InvalidSubject(t *testing.T) {
	ctx := context.TODO()
	mockClient := new(MockPaymentsClient)

	limits := &platmodel.LimitsStatus{
		Limits: &platmodel.GitOpsLimits{
			Applications: ptr(5),
			Clusters:     ptr(5),
		},
		Usage: &platmodel.GitOpsUsage{
			Applications: ptr(5),
			Clusters:     ptr(5),
		},
	}
	mockClient.On("GetLimitsStatus", ctx).Return(limits, nil)

	opts := ValidateLimitsOptions{failCondition: "exceeded", subject: "invalid-subject"}
	err := runValidateLimits(ctx, &opts, mockClient)

	assert.EqualError(t, err, "usage validation error: invalid subject: invalid-subject")
}
