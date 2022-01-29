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
		Close(step CliStepStatus, err error)
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
	cliEvent string = "csdp-cli"

	// Install
	InstallPhasePreCheckStart                         CliStep = "install.pre-check.phase.start"
	InstallStepPreCheckValidateRuntimeVersion         CliStep = "install.pre-check.step.validate-runtime-version"
	InstallStepPreCheckGetRuntimeName                 CliStep = "install.pre-check.step.get-runtime-name"
	InstallStepPreCheckRuntimeNameValidation          CliStep = "install.pre-check.step.runtime-name-validation"
	InstallStepPreCheckGetKubeContext                 CliStep = "install.pre-check.step.get-kube-context"
	InstallStepPreCheckEnsureRuntimeRepo              CliStep = "install.pre-check.step.ensure-runtime-repo"
	InstallStepPreCheckEnsureGitToken                 CliStep = "install.pre-check.step.ensure-git-token"
	InstallStepPreCheckEnsureIngressHost              CliStep = "install.pre-check.step.ensure-ingress-host"
	InstallStepPreCheckShouldInstallDemoResources     CliStep = "install.pre-check.step.should-install-demo-resources"
	InstallPhasePreCheckFinish                        CliStep = "install.pre-check.phase.finish"
	InstallPhaseRunPreCheckStart                      CliStep = "install.run.pre-check.phase.start"
	InstallStepRunPreCheckDownloadRuntimeDefinition   CliStep = "install.run.pre-check.step.download-runtime-definition"
	InstallStepRunPreCheckEnsureCliVersion            CliStep = "install.run.pre-check.step.ensure-cli-version"
	InstallStepRunPreCheckRuntimeCollision            CliStep = "install.run.pre-check.step.runtime-collision"
	InstallStepRunPreCheckExisitingRuntimes           CliStep = "install.run.pre-check.step.existing-runtimes"
	InstallStepRunPreCheckValidateClusterRequirements CliStep = "install.run.pre-check.step.validate-cluster-requirements"
	InstallPhaseRunPreCheckFinish                     CliStep = "install.run.pre-check.phase.finish"
	InstallPhaseStart                                 CliStep = "install.run.phase.start"
	InstallStepDownloadRuntimeDefinition              CliStep = "install.run.step.download-runtime-definition"
	InstallStepGetServerAddress                       CliStep = "install.run.step.get-server-address"
	InstallStepCreateRuntimeOnPlatform                CliStep = "install.run.step.create-runtime-on-platform"
	InstallStepBootstrapRepo                          CliStep = "install.run.step.bootstrap-repo"
	InstallStepCreateProject                          CliStep = "install.run.step.create-project"
	InstallStepCreateConfigMap                        CliStep = "install.run.step.create-codefresh-cm"
	InstallStepCreateComponents                       CliStep = "install.run.step.create-components"
	InstallStepInstallComponenets                     CliStep = "install.run.step.install-components"
	InstallStepCreateGitsource                        CliStep = "install.run.step.create-gitsource"
	InstallStepCreateMarketplaceGitsource             CliStep = "install.run.step.create-marketplace-gitsource"
	InstallStepCompleteRuntimeInstallation            CliStep = "install.run.step.complete-runtime-installation"
	InstallStepCreateDefaultGitIntegration            CliStep = "install.run.step.create-default-git-integration"
	InstallPhaseFinish                                CliStep = "install.run.phase.finish"

	// Uninstall
	UninstallPhasePreCheckStart                CliStep = "uninstall.pre-check.phase.start"
	UninstallStepPreCheckGetKubeContext        CliStep = "uninstall.pre-check.step.get-kube-context"
	UninstallStepPreCheckEnsureRuntimeName     CliStep = "uninstall.pre-check.step.ensure-runtime-name"
	UninstallStepPreCheckRuntimeNameValidation CliStep = "uninstall.pre-check.step.runtime-name-validation"
	UninstallStepPreCheckEnsureRuntimeRepo     CliStep = "uninstall.pre-check.step.ensure-runtime-repo"
	UninstallStepPreCheckEnsureGitToken        CliStep = "uninstall.pre-check.step.ensure-git-token"
	UninstallPhasePreCheckFinish               CliStep = "uninstall.pre-check.phase.finish"
	UninstallPhaseStart                        CliStep = "uninstall.run.phase.start"
	UninstallStepCheckRuntimeExists            CliStep = "uninstall.run.step.check-runtime-exists"
	UninstallStepUninstallRepo                 CliStep = "uninstall.run.step.uninstall-repo"
	UninstallStepDeleteRuntimeFromPlatform     CliStep = "uninstall.run.step.delete-runtime-from-platform"
	UninstallPhaseFinish                       CliStep = "uninstall.run.phase.finish"

	// Upgrade
	UpgradePhasePreCheckStart              CliStep = "upgrade.pre-check.phase.start"
	UpgradeStepPreCheckEnsureRuntimeName   CliStep = "upgrade.pre-check.step.ensure-runtime-name"
	UpgradeStepPreCheckEnsureRuntimeRepo   CliStep = "upgrade.pre-check.step.ensure-runtime-repo"
	UpgradeStepPreCheckEnsureGitToken      CliStep = "upgrade.pre-check.step.ensure-git-token"
	UpgradePhasePreCheckFinish             CliStep = "upgrade.pre-check.phase.finish"
	UpgradePhaseStart                      CliStep = "upgrade.run.phase.start"
	UpgradeStepDownloadRuntimeDefinition   CliStep = "upgrade.run.step.download-runtime-definition"
	UpgradeStepRunPreCheckEnsureCliVersion CliStep = "upgrade.run.step.ensure-cli-version"
	UpgradeStepGetRepo                     CliStep = "upgrade.run.step.get-repo"
	UpgradeStepLoadRuntimeDefinition       CliStep = "upgrade.run.step.load-runtime-definition"
	UpgradeStepUpgradeRuntime              CliStep = "upgrade.run.step.upgrade-runtime"
	UpgradeStepPushRuntimeDefinition       CliStep = "upgrade.run.step.push-runtime-definition"
	UpgradeStepCreateApp                   CliStep = "upgrade.run.step.create-app"
	UpgradePhaseFinish                     CliStep = "upgrade.run.phase.finish"

	// General
	SIGNAL_TERMINATION CliStep = "signal-termination"
	FINISH             CliStep = "run.finish"

	SUCCESS           CliStepStatus = "SUCCESS"
	FAILURE           CliStepStatus = "FAILURE"
	CANCELED          CliStepStatus = "CANCELED"
	ABRUPTLY_CANCELED CliStepStatus = "ABRUPTLY_CANCELED"

	InstallFlow   FlowType = "installation"
	UninstallFlow FlowType = "uninstallation"
	UpgradeFlow   FlowType = "upgrade"
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

func (r *segmentAnalyticsReporter) Close(status CliStepStatus, err error) {
	if status == "" {
		status = SUCCESS
		if err != nil {
			status = FAILURE
		}
	}

	log.G().Infof("Closing with status %s", status)

	r.ReportStep(CliStepData{
		Step:        FINISH,
		Status:      status,
		Description: "Finished",
		Err:         err,
	})

	if err := r.client.Close(); err != nil {
		log.G().Debugf("Failed to close segment client: %w", err)
	}
}

func (r *noopAnalyticsReporter) ReportStep(_ CliStepData) {
	// If no segmentWriteKey is provided this reporter will be used instead.
}

func (r *noopAnalyticsReporter) Close(_ CliStepStatus, _ error) {
}
