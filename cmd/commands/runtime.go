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
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/reporter"
	"github.com/codefresh-io/cli-v2/internal/store"
	"github.com/codefresh-io/cli-v2/internal/util"

	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/juju/ansiterm"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

type (
	RuntimeUninstallOptions struct {
		RuntimeName      string
		Force            bool
		DisableTelemetry bool
	}

	summaryLogLevels string
	summaryLog       struct {
		message string
		level   summaryLogLevels
	}
)

const (
	Success summaryLogLevels = "Success"
	Failed  summaryLogLevels = "Failed"
	Info    summaryLogLevels = "Info"
)

var summaryArr []summaryLog

func newRuntimeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "runtime",
		Short:             "Manage Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewRuntimeInstallCommand())
	cmd.AddCommand(newRuntimeListCommand())
	cmd.AddCommand(newRuntimeUninstallCommand())
	cmd.AddCommand(newRuntimeUpgradeCommand())
	cmd.AddCommand(newRuntimeLogsCommand())

	cmd.PersistentFlags().BoolVar(&store.Get().Silent, "silent", false, "Disables the command wizard")

	return cmd
}

func NewRuntimeInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "install [runtime_name]",
		Deprecated: "We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return errors.New(`We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.
As of January 30, 2024, CLI-based Runtimes are no longer supported.
If you're currently using CLI-based Hybrid GitOps Runtimes, we encourage you to migrate to Helm by following our migration guidelines (https://codefresh.io/docs/docs/installation/gitops/migrate-cli-runtimes-helm).
For Helm installation, review our documentation on installing Hybrid GitOps Runtimes (https://codefresh.io/docs/docs/installation/gitops/hybrid-gitops-helm-installation).`)
		},
	}

	return cmd
}

func runtimeUninstallCommandPreRunHandler(cmd *cobra.Command, args []string, opts *RuntimeUninstallOptions) error {
	var err error
	ctx := cmd.Context()

	handleCliStep(reporter.UninstallPhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.RuntimeName, err = ensureRuntimeName(ctx, args, nil)
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeName, "Ensuring runtime name", err, true, false)
	if err != nil {
		return err
	}

	rt, err := getRuntime(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	if rt.InstallationType == platmodel.InstallationTypeHelm {
		return errors.New("This runtime was installed using Helm, please use Helm to uninstall it as well.")
	}

	if !rt.Managed {
		return errors.New("The runtime uninstall command is only supported for managed runtimes")
	}

	return nil
}

func removeGitIntegrations(ctx context.Context, opts *RuntimeUninstallOptions) error {
	apClient, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client while removing git integration: %w", err)
	}

	integrations, err := apClient.GitIntegration().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to get list of git integrations: %w", err)
	}

	for _, intg := range integrations {
		if err = runGitIntegrationRemoveCommand(ctx, apClient, intg.Name); err != nil {
			command := util.Doc(fmt.Sprintf("\t<BIN> integration git remove %s", intg.Name))

			return fmt.Errorf(`%w. You can try to remove it manually by running: %s`, err, command)
		}
	}

	log.G(ctx).Info("Removed runtime git integrations")

	return nil
}

func newRuntimeListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		Short:   "List all Codefresh runtimes",
		Example: util.Doc("<BIN> runtime list"),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			return runRuntimeList(ctx)
		},
	}

	return cmd
}

func runRuntimeList(ctx context.Context) error {
	runtimes, err := cfConfig.NewClient().GraphQL().Runtime().List(ctx)
	if err != nil {
		return err
	}

	if len(runtimes) == 0 {
		log.G(ctx).Info("No runtimes were found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "NAME\tNAMESPACE\tCLUSTER\tVERSION\tSYNC_STATUS\tHEALTH_STATUS\tHEALTH_MESSAGE\tINSTALLATION_STATUS\tINGRESS_HOST\tINGRESS_CLASS")
	if err != nil {
		return err
	}

	for _, rt := range runtimes {
		name := rt.Metadata.Name
		namespace := "N/A"
		cluster := "N/A"
		version := "N/A"
		syncStatus := rt.SyncStatus
		healthStatus := rt.HealthStatus
		healthMessage := "N/A"
		installationStatus := rt.InstallationStatus
		ingressHost := "N/A"
		internalIngressHost := "N/A"
		ingressClass := "N/A"

		if rt.Managed {
			name = fmt.Sprintf("%s (hosted)", rt.Metadata.Name)
		}

		if rt.Metadata.Namespace != nil {
			namespace = *rt.Metadata.Namespace
		}

		if rt.Cluster != nil {
			cluster = *rt.Cluster
		}

		if rt.RuntimeVersion != nil {
			version = *rt.RuntimeVersion
		}

		if rt.HealthMessage != nil {
			healthMessage = *rt.HealthMessage
		}

		if rt.IngressHost != nil {
			ingressHost = *rt.IngressHost
		}

		if rt.InternalIngressHost != nil {
			internalIngressHost = *rt.InternalIngressHost
		}

		if rt.IngressClass != nil {
			ingressClass = *rt.IngressClass
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			namespace,
			cluster,
			version,
			syncStatus,
			healthStatus,
			healthMessage,
			installationStatus,
			ingressHost,
			internalIngressHost,
			ingressClass,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func newRuntimeUninstallCommand() *cobra.Command {
	var (
		opts            RuntimeUninstallOptions
		finalParameters map[string]string
	)

	cmd := &cobra.Command{
		Use:   "uninstall [RUNTIME_NAME]",
		Short: "Uninstall a Codefresh runtime",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export GIT_TOKEN=<token>

# or with the flag:

		--git-token <token>

# Deletes a runtime

	<BIN> runtime uninstall runtime-name --repo gitops_repo
`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			createAnalyticsReporter(ctx, reporter.UninstallFlow, opts.DisableTelemetry)

			err := runtimeUninstallCommandPreRunHandler(cmd, args, &opts)
			handleCliStep(reporter.UninstallPhasePreCheckFinish, "Finished pre run checks", err, true, false)
			if err != nil {
				if errors.Is(err, promptui.ErrInterrupt) {
					return fmt.Errorf("uninstallation canceled by user")
				}

				return fmt.Errorf("pre run error: %w", err)
			}

			finalParameters = map[string]string{
				"Codefresh context": cfConfig.GetCurrentContext().Name,
				"Runtime name":      opts.RuntimeName,
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime uninstall")
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runRuntimeUninstall(cmd.Context(), &opts)
			handleCliStep(reporter.UninstallPhaseFinish, "Uninstall phase finished", err, false, true)
			return err
		},
	}

	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be deleted")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "If true, will guarantee the runtime is removed from the platform, even in case of errors while cleaning the repo and the cluster")
	cmd.Flags().BoolVar(&opts.DisableTelemetry, "disable-telemetry", false, "If true, will disable the analytics reporting for the uninstall process")
	_ = cmd.Flags().MarkDeprecated("skip-checks", "this flag was removed, runtime must exist on platform for uninstall to run")

	return cmd
}

func runRuntimeUninstall(ctx context.Context, opts *RuntimeUninstallOptions) error {
	defer printSummaryToUser()

	handleCliStep(reporter.UninstallPhaseStart, "Uninstall phase started", nil, false, false)

	// check whether the runtime exists
	var err error
	handleCliStep(reporter.UninstallStepCheckRuntimeExists, "Checking if runtime exists", err, false, true)

	log.G(ctx).Infof("Uninstalling runtime \"%s\" - this process may take a few minutes...", opts.RuntimeName)

	err = removeRuntimeIsc(ctx, opts.RuntimeName)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveRuntimeIsc, "Removing runtime ISC", err, false, true)
	if err != nil {
		return fmt.Errorf("failed to remove runtime isc: %w", err)
	}

	err = removeGitIntegrations(ctx, opts)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveGitIntegrations, "Removing git integrations", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	err = deleteRuntimeFromPlatform(ctx, opts)
	handleCliStep(reporter.UninstallStepDeleteRuntimeFromPlatform, "Deleting runtime from platform", err, false, false)
	if err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	log.G(ctx).Infof("It may take up to 5 minutes until your hosted runtime will be fully deleted")
	if cfConfig.GetCurrentContext().DefaultRuntime == opts.RuntimeName {
		cfConfig.GetCurrentContext().DefaultRuntime = ""
	}

	uninstallDoneStr := fmt.Sprintf("Done uninstalling runtime \"%s\"", opts.RuntimeName)
	appendLogToSummary(uninstallDoneStr, nil)

	return nil
}

func removeRuntimeIsc(ctx context.Context, runtimeName string) error {
	iscRepo, err := getIscRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current user information: %w", err)
	}

	if iscRepo == "" {
		log.G(ctx).Info("Skipped removing runtime from ISC repo. ISC repo not defined")
		return nil
	}

	apClient, err := cfConfig.NewClient().AppProxy(ctx, runtimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client while removing runtime isc: %w", err)
	}

	intg, err := apClient.GitIntegration().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list git integrations: %w", err)
	}

	if len(intg) == 0 {
		log.G(ctx).Info("Skipped removing runtime from ISC repo. No git integrations")
		return nil
	}

	_, err = apClient.ISC().RemoveRuntimeFromIscRepo(ctx)
	if err == nil {
		log.G(ctx).Info("Removed runtime from ISC repo")
	}

	return err
}

func deleteRuntimeFromPlatform(ctx context.Context, opts *RuntimeUninstallOptions) error {
	log.G(ctx).Infof("Deleting runtime \"%s\" from the platform", opts.RuntimeName)
	_, err := cfConfig.NewClient().GraphQL().Runtime().Delete(ctx, opts.RuntimeName)
	if err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	log.G(ctx).Infof("Successfully deleted runtime \"%s\" from the platform", opts.RuntimeName)
	return nil
}

func newRuntimeUpgradeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "upgrade [RUNTIME_NAME]",
		Deprecated: "We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return errors.New(`We have transitioned our GitOps Runtimes from CLI-based to Helm-based installation.
As of January 30, 2024, CLI-based Runtimes are no longer supported.
If you're currently using CLI-based Hybrid GitOps Runtimes, we encourage you to migrate to Helm by following our migration guidelines (https://codefresh.io/docs/docs/installation/gitops/migrate-cli-runtimes-helm).
For Helm installation, review our documentation on installing Hybrid GitOps Runtimes (https://codefresh.io/docs/docs/installation/gitops/hybrid-gitops-helm-installation).`)
		},
	}

	return cmd
}

func newRuntimeLogsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs [--ingress-host <url>] [--download]",
		Short: "Work with current runtime logs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error = nil
			if isAllRequiredFlagsForDownloadRuntimeLogs() {
				err = downloadRuntimeLogs()
				if err == nil {
					log.G(cmd.Context()).Info("Runtime logs was downloaded successfully")
				}
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&store.Get().IsDownloadRuntimeLogs, "download", false, "If true, will download logs from all componnents that consist of current runtime")
	cmd.Flags().StringVar(&store.Get().IngressHost, "ingress-host", "", "Set runtime ingress host")
	return cmd
}

func isAllRequiredFlagsForDownloadRuntimeLogs() bool {
	return store.Get().IsDownloadRuntimeLogs && store.Get().IngressHost != ""
}

func downloadRuntimeLogs() error {
	downloadFileUrl := getDownloadFileUrl()
	response, err := http.Get(downloadFileUrl)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	fullFilename, err := getFullFilename(response)
	if err != nil {
		return err
	}
	return downloadFile(response, fullFilename)
}

func getDownloadFileUrl() string {
	ingressHost := store.Get().IngressHost
	appProxyPath := store.Get().AppProxyIngressPath
	regularExpression := regexp.MustCompile(`([^:])/{2,}`)
	url := fmt.Sprintf("%s/%s/api/applications/logs", ingressHost, appProxyPath)
	return regularExpression.ReplaceAllString(url, `$1/`)
}

func getFullFilename(response *http.Response) (string, error) {
	contentDisposition := response.Header.Get("Content-Disposition")
	_, params, err := mime.ParseMediaType(contentDisposition)
	if err != nil {
		return "", err
	}
	filename := params["filename"]
	processWorkingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	fullFilename := fmt.Sprintf("%s/%s", processWorkingDirectory, filename)
	return fullFilename, err
}

func downloadFile(response *http.Response, fullFilename string) error {
	fileDescriptor, err := os.Create(fullFilename)
	if err != nil {
		return err
	}
	defer func() { _ = fileDescriptor.Close() }()
	_, err = io.Copy(fileDescriptor, response.Body)
	return err
}

func handleCliStep(step reporter.CliStep, message string, err error, preStep bool, appendToLog bool) {
	r := reporter.G()
	status := reporter.SUCCESS
	if err != nil {
		if preStep {
			status = reporter.CANCELED
		} else {
			status = reporter.FAILURE
		}
	}

	r.ReportStep(reporter.CliStepData{
		Step:        step,
		Status:      status,
		Description: message,
		Err:         err,
	})

	if appendToLog {
		appendLogToSummary(message, err)
	}
}

func appendLogToSummary(message string, err error) {
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{message, Failed})
	} else {
		summaryArr = append(summaryArr, summaryLog{message, Success})
	}
}

func printSummaryToUser() {
	for i := 0; i < len(summaryArr); i++ {
		if summaryArr[i].level == Success {
			fmt.Printf("%s -> %v%s%v\n", summaryArr[i].message, GREEN, summaryArr[i].level, COLOR_RESET)
		} else if summaryArr[i].level == Failed {
			fmt.Printf("%s -> %v%s%v\n", summaryArr[i].message, RED, summaryArr[i].level, COLOR_RESET)
		} else {
			fmt.Printf("%s\n", summaryArr[i].message)
		}
	}
	//clear array to avoid double printing
	summaryArr = []summaryLog{}
}

func createAnalyticsReporter(ctx context.Context, flow reporter.FlowType, disableTelemetry bool) {
	if disableTelemetry {
		log.G().Debug("Analytics Reporter disabled by the --disable-telemetry flag.")
		return
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	user, err := cfConfig.GetUser(ctx)
	// If error, it will default to noop reporter
	if err != nil {
		log.G().Debug("Failed to get user from context")
		return
	}

	url := cfConfig.GetCurrentContext().URL

	if url != store.Get().DefaultAPI {
		log.G().Debug("Not reporting for local env")
		return
	}

	reporter.Init(user, flow)
}
