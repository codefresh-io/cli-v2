package reporter

import (
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/google/uuid"
	"gopkg.in/segmentio/analytics-go.v3"
)

var ar AnalyticsReporter = &noopAnalyticsReporter{}

type (
	AnalyticsReporter interface {
		ReportStep(CliStepData)
		Close()
	}

	CliStepData struct {
		Event       CliEventType
		Status      CliStepStatus
		Description string
		Err         error
	}

	CliEventType  string
	CliStepStatus string

	segmentAnalyticsReporter struct {
		client    analytics.Client
		flowId    string
		userId    string
		accountId string
	}

	noopAnalyticsReporter struct{}
)

const (
	// Install
	InstallStepPreChecks                   CliEventType = "install.pre-installation-checks"
	InstallStepDownloadRuntimeDefinitions  CliEventType = "install.download-runtime-definitions"
	InstallStepGetServerAddress            CliEventType = "install.get-server-address"
	InstallStepCreateRuntimeOnPlatform     CliEventType = "install.create-runtime-on-platform"
	InstallStepBootstrapRepo               CliEventType = "install.bootstrap-repo"
	InstallStepCreateProject               CliEventType = "install.create-project"
	InstallStepCreateConfigMap             CliEventType = "install.create-codefresh-cm"
	InstallStepCreateComponent             CliEventType = "install.create-component"
	InstallStepInstallComponenets          CliEventType = "install.install-components"
	InstallStepCreateGitsource             CliEventType = "install.create-gitsource"
	InstallStepCreateMarketplaceGitsource  CliEventType = "install.create-marketplace-gitsource"
	InstallStepCompleteRuntimeInstallation CliEventType = "install.complete-runtime-installation"
	InstallStepCreateDefaultGitIntegration CliEventType = "install.create-default-git-integration"

	// Uninstall
	UninstallStepCheckRuntimeExists            CliEventType = "uninstall.check-runtime-exists"
	UninstallStepUninstallRepo                 CliEventType = "uninstall.uninstall-repo"
	UninstallStepDeleteRuntimeFromPlatform     CliEventType = "uninstall.delete-runtime-from-platform"
	UninstallStepCompleteRuntimeUninstallation CliEventType = "uninstall.complete-runtime-uninstall"

	// General
	SIGNAL_TERMINATION CliEventType = "signal-termination"

	SUCCESS  CliStepStatus = "SUCCESS"
	FAILURE  CliStepStatus = "FAILURE"
	CANCELED CliStepStatus = "CANCELED"
)

// G returns the global reporter
func G() AnalyticsReporter {
	return ar
}

func Init(userId, accountId string) {
	writeKey := store.Get().SegmentWriteKey
	if writeKey == "" {
		log.G().Debug("No segment write key was provided. Using the noop reporter.")
		return
	}

	ar = &segmentAnalyticsReporter{
		client:    analytics.New(writeKey),
		flowId:    uuid.New().String(),
		userId:    userId,
		accountId: accountId,
	}
}

func (r *segmentAnalyticsReporter) ReportStep(step CliStepData) {
	properties := analytics.NewProperties().
		Set("accountId", r.accountId).
		Set("flowId", r.flowId).
		Set("description", step.Description).
		Set("status", step.Status)

	if step.Err != nil {
		properties = properties.Set("error", step.Err.Error())
	}

	log.G().Infof("Reporting track with data: %v", step)
	err := r.client.Enqueue(analytics.Track{
		UserId:     r.userId,
		Event:      string(step.Event),
		Properties: properties,
	})

	if err != nil {
		log.G().Info("Failed reporting: %w", err)
	}

	log.G().Info("Finished reporting")
}

func (r *segmentAnalyticsReporter) Close() {
	if err := r.client.Close(); err != nil {
		log.G().Errorf("Failed to close segment client: %w", err)
	}
}

func (r *noopAnalyticsReporter) ReportStep(_ CliStepData) {
	// If no segmentWriteKey is provided this reporter will be used instead.
}

func (r *noopAnalyticsReporter) Close() {
}
