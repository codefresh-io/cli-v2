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
	"strings"
	"sync"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/reporter"
	"github.com/codefresh-io/cli-v2/pkg/runtime"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"

	"github.com/Masterminds/semver/v3"
	apcmd "github.com/argoproj-labs/argocd-autopilot/cmd/commands"
	"github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	appset "github.com/argoproj/applicationset/api/v1alpha1"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	argocdv1alpha1cs "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"
	"github.com/juju/ansiterm"
	"github.com/manifoldco/promptui"
	"github.com/rkrmr33/checklist"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	RuntimeUninstallOptions struct {
		RuntimeName      string
		Timeout          time.Duration
		CloneOpts        *apgit.CloneOptions
		KubeFactory      kube.Factory
		SkipChecks       bool
		Force            bool
		FastExit         bool
		DisableTelemetry bool
		Managed          bool

		kubeContext            string
		skipAutopilotUninstall bool
	}

	RuntimeUpgradeOptions struct {
		RuntimeName               string
		Version                   *semver.Version
		CloneOpts                 *apgit.CloneOptions
		CommonConfig              *runtime.CommonConfig
		SuggestedSharedConfigRepo string
		DisableTelemetry          bool

		branch string
	}

	gvr struct {
		resourceName string
		group        string
		version      string
	}

	reporterCreateOptions struct {
		reporterName string
		gvr          []gvr
		saName       string
		IsInternal   bool
		clusterScope bool
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

func NewRuntimeCommand() *cobra.Command {
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
	cmd.AddCommand(NewRuntimeListCommand())
	cmd.AddCommand(NewRuntimeUninstallCommand())
	cmd.AddCommand(NewRuntimeUpgradeCommand())
	cmd.AddCommand(NewRuntimeLogsCommand())

	cmd.PersistentFlags().BoolVar(&store.Get().Silent, "silent", false, "Disables the command wizard")

	return cmd
}

func runtimeUninstallCommandPreRunHandler(cmd *cobra.Command, args []string, opts *RuntimeUninstallOptions) error {
	var err error
	ctx := cmd.Context()

	handleCliStep(reporter.UninstallPhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.RuntimeName, err = ensureRuntimeName(ctx, args, true)
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeName, "Ensuring runtime name", err, true, false)
	if err != nil {
		return err
	}

	if !opts.SkipChecks {
		opts.Managed, err = isRuntimeManaged(ctx, opts.RuntimeName)
		if err != nil {
			return err
		}
	}

	if !opts.Managed {
		opts.kubeContext, err = getKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
	}
	handleCliStep(reporter.UninstallStepPreCheckGetKubeContext, "Getting kube context name", err, true, false)
	if err != nil {
		return err
	}

	if !opts.Managed && !opts.SkipChecks {
		kubeconfig := cmd.Flag("kubeconfig").Value.String()
		err = ensureRuntimeOnKubeContext(ctx, kubeconfig, opts.RuntimeName, opts.kubeContext)

		if err != nil && opts.Force {
			log.G(ctx).Warn("Failed to verify runtime is installed on the selected kubernetes context, installation repository will not be cleaned")
			err = nil
			opts.skipAutopilotUninstall = true // will not touch the cluster and repo
		}
	}
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeOnKubeContext, "Ensuring runtime is on the kube context", err, true, false)
	if err != nil {
		return err
	}

	if !opts.Managed {
		err = ensureRepo(cmd, opts.RuntimeName, opts.CloneOpts, true)
	}
	handleCliStep(reporter.UninstallStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	if !opts.Managed {
		err = ensureGitToken(cmd, nil, opts.CloneOpts)
	}
	handleCliStep(reporter.UninstallStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	return nil
}

func runtimeUpgradeCommandPreRunHandler(cmd *cobra.Command, args []string, opts *RuntimeUpgradeOptions) error {
	var err error
	ctx := cmd.Context()

	handleCliStep(reporter.UpgradePhasePreCheckStart, "Starting pre checks", nil, true, false)

	opts.RuntimeName, err = ensureRuntimeName(ctx, args, false)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureRuntimeName, "Ensuring runtime name", err, true, false)
	if err != nil {
		return err
	}

	isManaged, err := isRuntimeManaged(ctx, opts.RuntimeName)
	handleCliStep(reporter.UpgradeStepPreCheckIsManagedRuntime, "Checking if runtime is hosted", err, true, false)
	if err != nil {
		return err
	}

	if isManaged {
		return fmt.Errorf("manual upgrades are not allowed for hosted runtimes and are managed by Codefresh operational team")
	}

	err = ensureRepo(cmd, opts.RuntimeName, opts.CloneOpts, true)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureRuntimeRepo, "Getting runtime repo", err, true, false)
	if err != nil {
		return err
	}

	err = ensureGitToken(cmd, nil, opts.CloneOpts)
	handleCliStep(reporter.UpgradeStepPreCheckEnsureGitToken, "Getting git token", err, true, false)
	if err != nil {
		return err
	}

	if opts.SuggestedSharedConfigRepo != "" {
		sharedConfigRepo, err := setIscRepo(ctx, opts.SuggestedSharedConfigRepo)
		if err != nil {
			return fmt.Errorf("failed to ensure shared config repo for account: %w", err)
		}
		log.G(ctx).Infof("using repo '%s' as shared config repo for this account", sharedConfigRepo)
	}

	return nil
}

func removeGitIntegrations(ctx context.Context, opts *RuntimeUninstallOptions) error {
	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, opts.RuntimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client while removing git integration: %w", err)
	}

	integrations, err := appProxyClient.GitIntegrations().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to get list of git integrations: %w", err)
	}

	for _, intg := range integrations {
		if err = RunGitIntegrationRemoveCommand(ctx, appProxyClient, intg.Name); err != nil {
			command := util.Doc(fmt.Sprintf("\t<BIN> integration git remove %s", intg.Name))

			return fmt.Errorf(`%w. You can try to remove it manually by running: %s`, err, command)
		}
	}

	return nil
}

func getComponentChecklistState(c model.Component) (checklist.ListItemState, checklist.ListItemInfo) {
	state := checklist.Waiting
	name := strings.TrimPrefix(c.Metadata.Name, fmt.Sprintf("%s-", c.Metadata.Runtime))
	version := "N/A"
	syncStatus := "N/A"
	healthStatus := "N/A"
	errs := ""

	if c.Version != "" {
		version = c.Version
	}

	if c.Self != nil && c.Self.Status != nil {
		syncStatus = string(c.Self.Status.SyncStatus)

		if c.Self.Status.HealthStatus != nil {
			healthStatus = string(*c.Self.Status.HealthStatus)
		}

		if len(c.Self.Errors) > 0 {
			// use the first sync error due to lack of space
			for _, err := range c.Self.Errors {
				se, ok := err.(model.SyncError)
				if ok && se.Level == model.ErrorLevelsError {
					errs = se.Message
					state = checklist.Error
				}
			}
		}
	}

	if healthStatus == string(model.HealthStatusHealthy) && syncStatus == string(model.SyncStatusSynced) {
		state = checklist.Ready
	}

	return state, []string{name, healthStatus, syncStatus, version, errs}
}

func NewRuntimeListCommand() *cobra.Command {
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
	runtimes, err := cfConfig.NewClient().V2().Runtime().List(ctx)
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

func NewRuntimeUninstallCommand() *cobra.Command {
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
				"Codefresh context": cfConfig.CurrentContext,
				"Runtime name":      opts.RuntimeName,
			}

			if !opts.Managed {
				finalParameters["Kube context"] = opts.kubeContext
				finalParameters["Repository URL"] = opts.CloneOpts.Repo
				opts.CloneOpts.Parse()
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime uninstall")
			if err != nil {
				return err
			}

			opts.Timeout = store.Get().WaitTimeout

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runRuntimeUninstall(cmd.Context(), &opts)
			handleCliStep(reporter.UninstallPhaseFinish, "Uninstall phase finished", err, false, true)
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.SkipChecks, "skip-checks", false, "If true, will not verify that runtime exists before uninstalling")
	cmd.Flags().DurationVar(&store.Get().WaitTimeout, "wait-timeout", store.Get().WaitTimeout, "How long to wait for the runtime components to be deleted")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "If true, will guarantee the runtime is removed from the platform, even in case of errors while cleaning the repo and the cluster")
	cmd.Flags().BoolVar(&opts.FastExit, "fast-exit", false, "If true, will not wait for deletion of cluster resources. This means that full resource deletion will not be verified")
	cmd.Flags().BoolVar(&opts.DisableTelemetry, "disable-telemetry", false, "If true, will disable the analytics reporting for the uninstall process")

	opts.CloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{
		CloneForWrite: true,
		Optional:      true,
	})
	opts.KubeFactory = kube.AddFlags(cmd.Flags())

	return cmd
}

func runRuntimeUninstall(ctx context.Context, opts *RuntimeUninstallOptions) error {
	defer printSummaryToUser()

	handleCliStep(reporter.UninstallPhaseStart, "Uninstall phase started", nil, false, false)

	// check whether the runtime exists
	var err error
	if !opts.SkipChecks {
		_, err = cfConfig.NewClient().V2().Runtime().Get(ctx, opts.RuntimeName)
	}
	handleCliStep(reporter.UninstallStepCheckRuntimeExists, "Checking if runtime exists", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--skip-checks\" flag", Info})
		return err
	}

	log.G(ctx).Infof("Uninstalling runtime \"%s\" - this process may take a few minutes...", opts.RuntimeName)

	err = removeGitIntegrations(ctx, opts)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveGitIntegrations, "Removing git integrations", err, false, true)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	err = removeRuntimeIsc(ctx, opts.RuntimeName)
	if opts.Force {
		err = nil
	}
	handleCliStep(reporter.UninstallStepRemoveRuntimeIsc, "Removing runtime ISC", err, false, true)
	if err != nil {
		return fmt.Errorf("failed to remove runtime isc: %w", err)
	}

	if !opts.skipAutopilotUninstall {
		subCtx, cancel := context.WithCancel(ctx)
		go func() {
			if err := printApplicationsState(subCtx, opts.RuntimeName, opts.KubeFactory, opts.Managed); err != nil {
				log.G(ctx).WithError(err).Debug("failed to print uninstallation progress")
			}
		}()

		if !opts.Managed {
			err = apcmd.RunRepoUninstall(ctx, &apcmd.RepoUninstallOptions{
				Namespace:       opts.RuntimeName,
				KubeContextName: opts.kubeContext,
				Timeout:         opts.Timeout,
				CloneOptions:    opts.CloneOpts,
				KubeFactory:     opts.KubeFactory,
				Force:           opts.Force,
				FastExit:        opts.FastExit,
			})
		}
		cancel() // to tell the progress to stop displaying even if it's not finished
		if opts.Force {
			err = nil
		}
	}
	handleCliStep(reporter.UninstallStepUninstallRepo, "Uninstalling repo", err, false, !opts.Managed && !opts.skipAutopilotUninstall)
	if err != nil {
		summaryArr = append(summaryArr, summaryLog{"you can attempt to uninstall again with the \"--force\" flag", Info})
		return err
	}

	log.G(ctx).Infof("Deleting runtime '%s' from platform", opts.RuntimeName)
	if opts.Managed {
		_, err = cfConfig.NewClient().V2().Runtime().DeleteManaged(ctx, opts.RuntimeName)
	} else {
		err = deleteRuntimeFromPlatform(ctx, opts)
	}
	handleCliStep(reporter.UninstallStepDeleteRuntimeFromPlatform, "Deleting runtime from platform", err, false, !opts.Managed)
	if err != nil {
		return fmt.Errorf("failed to delete runtime from the platform: %w", err)
	}

	if cfConfig.GetCurrentContext().DefaultRuntime == opts.RuntimeName {
		cfConfig.GetCurrentContext().DefaultRuntime = ""
	}

	uninstallDoneStr := fmt.Sprintf("Done uninstalling runtime \"%s\"", opts.RuntimeName)
	appendLogToSummary(uninstallDoneStr, nil)

	return nil
}

func printApplicationsState(ctx context.Context, runtime string, f kube.Factory, managed bool) error {
	if managed {
		return nil
	}

	apps := map[string]*argocdv1alpha1.Application{}
	lock := sync.Mutex{}

	rc, err := f.ToRESTConfig()
	if err != nil {
		return err
	}

	cs, err := argocdv1alpha1cs.NewForConfig(rc)
	if err != nil {
		return err
	}

	appIf := cs.ArgoprojV1alpha1().Applications(runtime)
	componentsLabelSelector := fmt.Sprintf("%s=%s", store.Get().LabelKeyCFType, store.Get().CFComponentType)

	curApps, err := appIf.List(ctx, metav1.ListOptions{LabelSelector: componentsLabelSelector})
	if err != nil {
		return err
	}

	if len(curApps.Items) == 0 {
		// all apps already deleted nothing to wait for
		return nil
	}

	for i, a := range curApps.Items {
		apps[a.Name] = &curApps.Items[i]
	}

	// refresh components state
	go func() {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			curApps, err := appIf.List(ctx, metav1.ListOptions{LabelSelector: componentsLabelSelector})
			if err != nil {
				log.G(ctx).WithError(err).Debug("failed to refresh components state")
				continue
			}

			newApps := make(map[string]*argocdv1alpha1.Application, len(curApps.Items))
			for i, a := range curApps.Items {
				newApps[a.Name] = &curApps.Items[i]
			}

			lock.Lock()
			// update existing
			for i, a := range curApps.Items {
				apps[a.Name] = &curApps.Items[i]
			}

			// clear deleted apps
			for name := range apps {
				if _, ok := newApps[name]; !ok {
					delete(apps, name)
				}
			}
			lock.Unlock()
		}
	}()

	checkers := make([]checklist.Checker, len(curApps.Items))
	for i, a := range curApps.Items {
		name := a.Name
		checkers[i] = func(_ context.Context) (checklist.ListItemState, checklist.ListItemInfo) {
			lock.Lock()
			defer lock.Unlock()
			return getApplicationChecklistState(name, apps[name], runtime)
		}
	}

	cl := checklist.NewCheckList(
		os.Stdout,
		checklist.ListItemInfo{"COMPONENT", "STATUS"},
		checkers,
		&checklist.CheckListOptions{
			WaitAllReady: true,
		},
	)

	if err := cl.Start(ctx); err != nil && ctx.Err() == nil {
		return err
	}

	return nil
}

func getApplicationChecklistState(name string, a *argocdv1alpha1.Application, runtime string) (checklist.ListItemState, checklist.ListItemInfo) {
	state := checklist.Waiting
	name = strings.TrimPrefix(name, fmt.Sprintf("%s-", runtime))
	status := "N/A"

	if a == nil {
		status = "Deleted"
		state = checklist.Ready
	} else if string(a.Status.Health.Status) != "" {
		status = string(a.Status.Health.Status)
	}

	return state, []string{name, status}
}

func removeRuntimeIsc(ctx context.Context, runtimeName string) error {
	me, err := cfConfig.NewClient().V2().UsersV2().GetCurrent(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current user information: %w", err)
	}

	if me.ActiveAccount.SharedConfigRepo == nil || *me.ActiveAccount.SharedConfigRepo == "" {
		log.G(ctx).Info("Skipped removing runtime from ISC repo. ISC repo not defined")
		return nil
	}

	appProxyClient, err := cfConfig.NewClient().AppProxy(ctx, runtimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return fmt.Errorf("failed to build app-proxy client while removing runtime isc: %w", err)
	}

	intg, err := appProxyClient.GitIntegrations().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list git integrations: %w", err)
	}

	if len(intg) == 0 {
		log.G(ctx).Info("Skipped removing runtime from ISC repo. No git integrations")
		return nil
	}

	_, err = appProxyClient.AppProxyIsc().RemoveRuntimeFromIscRepo(ctx)
	if err == nil {
		log.G(ctx).Info("Removed runtime from ISC repo")
	}

	return err
}

func deleteRuntimeFromPlatform(ctx context.Context, opts *RuntimeUninstallOptions) error {
	log.G(ctx).Infof("Deleting runtime \"%s\" from the platform", opts.RuntimeName)
	_, err := cfConfig.NewClient().V2().Runtime().Delete(ctx, opts.RuntimeName)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Successfully deleted runtime \"%s\" from the platform", opts.RuntimeName)
	return nil
}

func NewRuntimeUpgradeCommand() *cobra.Command {
	var (
		versionStr      string
		finalParameters map[string]string
		opts            RuntimeUpgradeOptions
	)

	cmd := &cobra.Command{
		Use:   "upgrade [RUNTIME_NAME]",
		Short: "Upgrade a Codefresh runtime",
		Args:  cobra.MaximumNArgs(1),
		Example: util.Doc(`
# To run this command you need to create a personal access token for your git provider
# and provide it using:

		export GIT_TOKEN=<token>

# or with the flag:

		--git-token <token>

# Upgrade a runtime to version v0.0.30

	<BIN> runtime upgrade runtime-name --version 0.0.30 --repo gitops_repo
`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			createAnalyticsReporter(ctx, reporter.UpgradeFlow, opts.DisableTelemetry)

			err := runtimeUpgradeCommandPreRunHandler(cmd, args, &opts)
			handleCliStep(reporter.UpgradePhasePreCheckFinish, "Finished pre run checks", err, true, false)
			if err != nil {
				if errors.Is(err, promptui.ErrInterrupt) {
					return fmt.Errorf("upgrade canceled by user")
				}
				return fmt.Errorf("pre run error: %w", err)
			}

			finalParameters = map[string]string{
				"Codefresh context": cfConfig.CurrentContext,
				"Runtime name":      opts.RuntimeName,
				"Repository URL":    opts.CloneOpts.Repo,
			}

			if versionStr != "" {
				finalParameters["Version"] = versionStr
			}

			err = getApprovalFromUser(ctx, finalParameters, "runtime upgrade")
			if err != nil {
				return err
			}

			opts.CloneOpts.Parse()
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			ctx := cmd.Context()

			if versionStr != "" {
				opts.Version, err = semver.NewVersion(versionStr)
				if err != nil {
					return err
				}
			}

			opts.CommonConfig = &runtime.CommonConfig{
				CodefreshBaseURL: cfConfig.GetCurrentContext().URL,
			}

			err = runRuntimeUpgrade(ctx, &opts)
			handleCliStep(reporter.UpgradePhaseFinish, "Runtime upgrade phase finished", err, false, false)
			return err
		},
	}

	cmd.Flags().StringVar(&versionStr, "version", "", "The runtime version to upgrade to, defaults to latest")
	cmd.Flags().StringVar(&opts.SuggestedSharedConfigRepo, "shared-config-repo", "", "URL to the shared configurations repo. (default: <installation-repo> or the existing one for this account)")
	cmd.Flags().BoolVar(&opts.DisableTelemetry, "disable-telemetry", false, "If true, will disable analytics reporting for the upgrade process")
	cmd.Flags().BoolVar(&store.Get().SetDefaultResources, "set-default-resources", false, "If true, will set default requests and limits on all of the runtime components")
	cmd.Flags().StringVar(&opts.branch, "branch", "", "Install runtime from a specific branch (dev-time only)")
	opts.CloneOpts = apu.AddCloneFlags(cmd, &apu.CloneFlagsOptions{CloneForWrite: true})

	util.Die(cmd.Flags().MarkHidden("branch"))

	return cmd
}

func runRuntimeUpgrade(ctx context.Context, opts *RuntimeUpgradeOptions) error {
	handleCliStep(reporter.UpgradePhaseStart, "Runtime upgrade phase started", nil, false, true)

	log.G(ctx).Info("Downloading runtime definition")
	newRt, err := runtime.Download(opts.Version, opts.RuntimeName, opts.branch)
	handleCliStep(reporter.UpgradeStepDownloadRuntimeDefinition, "Downloading runtime definition", err, true, false)
	if err != nil {
		return fmt.Errorf("failed to download runtime definition: %w", err)
	}

	if newRt.Spec.DefVersion.GreaterThan(store.Get().MaxDefVersion) {
		err = fmt.Errorf("please upgrade your cli version before upgrading to %s", newRt.Spec.Version)
	}
	handleCliStep(reporter.UpgradeStepRunPreCheckEnsureCliVersion, "Checking CLI version", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Info("Cloning installation repository")
	r, fs, err := opts.CloneOpts.GetRepo(ctx)
	handleCliStep(reporter.UpgradeStepGetRepo, "Getting repository", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Info("Loading current runtime definition")
	curRt, err := runtime.Load(fs, fs.Join(apstore.Default.BootsrtrapDir, opts.RuntimeName+".yaml"))
	handleCliStep(reporter.UpgradeStepLoadRuntimeDefinition, "Loading runtime definition", err, true, false)
	if err != nil {
		return fmt.Errorf("failed to load current runtime definition: %w", err)
	}

	if !newRt.Spec.Version.GreaterThan(curRt.Spec.Version) {
		err = fmt.Errorf("current runtime version (%s) is greater than or equal to the specified version (%s)", curRt.Spec.Version, newRt.Spec.Version)
	}
	handleCliStep(reporter.UpgradeStepLoadRuntimeDefinition, "Comparing runtime versions", err, true, false)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("Upgrading runtime \"%s\" to version: v%s", opts.RuntimeName, newRt.Spec.Version)
	newComponents, err := curRt.Upgrade(fs, newRt, opts.CommonConfig)
	handleCliStep(reporter.UpgradeStepUpgradeRuntime, "Upgrading runtime", err, false, false)
	if err != nil {
		return fmt.Errorf("failed to upgrade runtime: %w", err)
	}

	log.G(ctx).Info("Pushing new runtime definition")
	err = apu.PushWithMessage(ctx, r, fmt.Sprintf("Upgraded to %s", newRt.Spec.Version))
	handleCliStep(reporter.UpgradeStepPushRuntimeDefinition, "Pushing new runtime definition", err, false, false)
	if err != nil {
		return err
	}

	for _, component := range newComponents {
		log.G(ctx).Infof("Installing new component \"%s\"", component.Name)
		component.IsInternal = true
		err = component.CreateApp(ctx, nil, opts.CloneOpts, opts.RuntimeName, store.Get().CFComponentType, "", "")
		if err != nil {
			err = fmt.Errorf("failed to create \"%s\" application: %w", component.Name, err)
			break
		}
	}

	handleCliStep(reporter.UpgradeStepInstallNewComponents, "Install new components", err, false, false)

	log.G(ctx).Infof("Runtime upgraded to version: v%s", newRt.Spec.Version)

	return nil
}

func NewRuntimeLogsCommand() *cobra.Command {
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
	defer response.Body.Close()
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
	defer fileDescriptor.Close()
	_, err = io.Copy(fileDescriptor, response.Body)
	return err
}

var getProjectInfoFromFile = func(repofs fs.FS, name string) (*argocdv1alpha1.AppProject, *appset.ApplicationSet, error) {
	proj := &argocdv1alpha1.AppProject{}
	appSet := &appset.ApplicationSet{}
	if err := repofs.ReadYamls(name, proj, appSet); err != nil {
		return nil, nil, err
	}

	return proj, appSet, nil
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

	user, err := cfConfig.GetCurrentContext().GetUser(ctx)
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
