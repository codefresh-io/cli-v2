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

package reporter

import (
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
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
		Step        CliStep
		Status      CliStepStatus
		Description string
		Err         error
	}

	CliStep       string
	CliStepStatus string
	FlowType      string

	segmentAnalyticsReporter struct {
		client      analytics.Client
		flowType    FlowType
		flowId      string
		userId      string
		userName    string
		accountId   string
		accountName string
	}

	noopAnalyticsReporter struct{}
)

const (
	cliEvent string = "cli-runtime-operations"

	// Install
	InstallStepPreChecks                   CliStep = "install.pre-installation-checks"
	InstallStepDownloadRuntimeDefinitions  CliStep = "install.download-runtime-definitions"
	InstallStepGetServerAddress            CliStep = "install.get-server-address"
	InstallStepCreateRuntimeOnPlatform     CliStep = "install.create-runtime-on-platform"
	InstallStepBootstrapRepo               CliStep = "install.bootstrap-repo"
	InstallStepCreateProject               CliStep = "install.create-project"
	InstallStepCreateConfigMap             CliStep = "install.create-codefresh-cm"
	InstallStepCreateComponent             CliStep = "install.create-component"
	InstallStepInstallComponenets          CliStep = "install.install-components"
	InstallStepCreateGitsource             CliStep = "install.create-gitsource"
	InstallStepCreateMarketplaceGitsource  CliStep = "install.create-marketplace-gitsource"
	InstallStepCompleteRuntimeInstallation CliStep = "install.complete-runtime-installation"
	InstallStepCreateDefaultGitIntegration CliStep = "install.create-default-git-integration"

	// Uninstall
	UninstallStepCheckRuntimeExists            CliStep = "uninstall.check-runtime-exists"
	UninstallStepUninstallRepo                 CliStep = "uninstall.uninstall-repo"
	UninstallStepDeleteRuntimeFromPlatform     CliStep = "uninstall.delete-runtime-from-platform"
	UninstallStepCompleteRuntimeUninstallation CliStep = "uninstall.complete-runtime-uninstall"

	// General
	SIGNAL_TERMINATION CliStep = "signal-termination"

	SUCCESS  CliStepStatus = "SUCCESS"
	FAILURE  CliStepStatus = "FAILURE"
	CANCELED CliStepStatus = "CANCELED"

	InstallFlow   FlowType = "installation"
	UninstallFlow FlowType = "uninstallation"
)

// G returns the global reporter
func G() AnalyticsReporter {
	return ar
}

func Init(user *codefresh.User, flow FlowType) {
	writeKey := store.Get().SegmentWriteKey
	if writeKey == "" {
		log.G().Debug("No segment write key was provided. Using the noop reporter.")
		return
	}

	account := user.GetActiveAccount()

	ar = &segmentAnalyticsReporter{
		client:      analytics.New(writeKey),
		flowId:      uuid.New().String(),
		flowType:    flow,
		userId:      user.ID,
		userName:    user.Name,
		accountId:   account.ID,
		accountName: account.Name,
	}
}

func (r *segmentAnalyticsReporter) ReportStep(data CliStepData) {
	properties := analytics.NewProperties().
		Set("accountId", r.accountId).
		Set("accountName", r.accountName).
		Set("userName", r.userName).
		Set("flowId", r.flowId).
		Set("flowType", r.flowType).
		Set("description", data.Description).
		Set("step", data.Step).
		Set("status", data.Status)

	if data.Err != nil {
		properties = properties.Set("error", data.Err.Error())
	}

	err := r.client.Enqueue(analytics.Track{
		UserId:     r.userId,
		Event:      cliEvent,
		Properties: properties,
	})

	if err != nil {
		log.G().Debugf("Failed reporting to segment: %w", err)
	}
}

func (r *segmentAnalyticsReporter) Close() {
	if err := r.client.Close(); err != nil {
		log.G().Debugf("Failed to close segment client: %w", err)
	}
}

func (r *noopAnalyticsReporter) ReportStep(_ CliStepData) {
	// If no segmentWriteKey is provided this reporter will be used instead.
}

func (r *noopAnalyticsReporter) Close() {
}
