package util

import (
	"github.com/codefresh-io/cli-v2/pkg/store"
	"gopkg.in/segmentio/analytics-go.v3"
)

type (
	AnalyticsReporter interface {
		ReportStep(CliStepData)
	}

	CliStepData struct {
		Event       CliEventType
		Status      CliStepStatus
		Description string
		Err         error
	}
	segmentAnalyticsReporter struct {
		client    analytics.Client
		userId    string
		accountId string
	}

	noopAnalyticsReporter struct{}

	CliEventType  string
	CliStepStatus string
)

const (
	// Install
	PRE_INSTALLATION_CHECKS        CliEventType = "install.pre-installation-checks"
	DOWNLOAD_RUNTIME_DEFINITIONS   CliEventType = "install.download-runtime-definitions"
	GET_SERVER_ADDRESS             CliEventType = "install.get-server-address"
	CREATE_RUNTIME_ON_PLATFORM     CliEventType = "install.create-runtime-on-platform"
	BOOTSTRAP_REPO                 CliEventType = "install.bootstrap-repo"
	CREATE_PROJECT                 CliEventType = "install.create-project"
	CREATE_CODEFRESH_CM            CliEventType = "install.create-codefresh-cm"
	CREATE_COMPONENT               CliEventType = "install.create-component"
	INSTALL_COMPONENTS             CliEventType = "install.install-components"
	CREATE_GITSOURCE               CliEventType = "install.create-gitsource"
	CREATE_MARKETPLACE_GITSOURCE   CliEventType = "install.create-marketplace-gitsource"
	COMPLETE_RUNTIME_INSTALLATION  CliEventType = "install.complete-runtime-installation"
	CREATE_DEFAULT_GIT_INTEGRATION CliEventType = "install.create-default-git-integration"

	// Uninstall
	CHECK_RUNTIME_EXISTS         CliEventType = "uninstall.check-runtime-exists"
	UNINSTALL_REPO               CliEventType = "uninstall.uninstall-repo"
	DELETE_RUNTIME_FROM_PLATFORM CliEventType = "uninstall.delete-runtime-from-platform"
	COMPLETE_RUNTIME_UNINSTALL   CliEventType = "uninstall.complete-runtime-uninstall"

	// General
	SIGNAL_TERMINATION CliEventType = "signal-termination"

	SUCCESS  CliStepStatus = "SUCCESS"
	FAILURE  CliStepStatus = "FAILURE"
	CANCELED CliStepStatus = "CANCELED"
)

func NewAnalyticsReporter(userId, accountId string) AnalyticsReporter {
	writeKey := store.Get().SegmentWriteKey
	if writeKey == "" {
		return &noopAnalyticsReporter{}
	}

	return &segmentAnalyticsReporter{
		client:    analytics.New(writeKey),
		userId:    userId,
		accountId: accountId,
	}
}

func (s *segmentAnalyticsReporter) ReportStep(step CliStepData) {
	properties := analytics.NewProperties().
		Set("status", step.Status).
		Set("description", step.Description).
		Set("accountId", s.accountId)

	if step.Err != nil {
		properties = properties.Set("error", step.Err.Error())
	}

	s.client.Enqueue(analytics.Track{
		UserId:     s.userId,
		Event:      string(step.Event),
		Properties: properties,
	})
}

func (s *noopAnalyticsReporter) ReportStep(_ CliStepData) {
	// If no segmentWriteKey is provided this reporter will be used instead.
}
