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
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/model"

	"github.com/Masterminds/semver/v3"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	kusttypes "sigs.k8s.io/kustomize/api/types"
)

type (
	ClusterAddOptions struct {
		runtimeName string
		clusterName string
		kubeContext string
		kubeconfig  string
		dryRun      bool
		kubeFactory kube.Factory
	}

	ClusterRemoveOptions struct {
		runtimeName string
		server      string
	}

	ClusterCreateArgoRolloutsOptions struct {
		runtimeName string
		server      string
		namespace   string
	}
)

var minAddClusterSupportedVersion = semver.MustParse("0.0.283")

func NewClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Hidden:            true, // until app-proxy is working correctly
		Use:               "cluster",
		Short:             "Manage clusters of Codefresh runtimes",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(newClusterAddCommand())
	cmd.AddCommand(newClusterRemoveCommand())
	cmd.AddCommand(newClusterListCommand())
	cmd.AddCommand(newClusterCreateArgoRolloutsCommand())

	return cmd
}

func newClusterAddCommand() *cobra.Command {
	var opts ClusterAddOptions

	cmd := &cobra.Command{
		Use:     "add [RUNTIME_NAME]",
		Short:   "Add a cluster to a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster add my-runtime --context my-context`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()

			opts.runtimeName, err = ensureRuntimeName(ctx, args, true)
			if err != nil {
				return err
			}

			opts.kubeContext, err = ensureKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
			if err != nil {
				return err
			}

			err = setClusterName(cmd.Context(), &opts)

			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterAdd(cmd.Context(), &opts)
		},
	}

	cmd.Flags().StringVar(&opts.clusterName, "name", "", "Name of the cluster. If omitted, will use the context name")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "")
	opts.kubeFactory = kube.AddFlags(cmd.Flags())

	return cmd
}

func runClusterAdd(ctx context.Context, opts *ClusterAddOptions) error {
	runtime, err := cfConfig.NewClient().V2().Runtime().Get(ctx, opts.runtimeName)
	if err != nil {
		return err
	}

	if runtime.RuntimeVersion == nil {
		return fmt.Errorf("runtime \"%s\" has no version", opts.runtimeName)
	}

	version := semver.MustParse(*runtime.RuntimeVersion)
	if version.LessThan(minAddClusterSupportedVersion) {
		return fmt.Errorf("runtime \"%s\" does not support this command. Minimal required version is %s", opts.runtimeName, minAddClusterSupportedVersion)
	}

	if runtime.IngressHost == nil {
		return fmt.Errorf("runtime \"%s\" is missing an ingress URL", opts.runtimeName)
	}

	ingressUrl := *runtime.IngressHost
	server, err := util.KubeServerByContextName(opts.kubeContext, opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("failed getting server for context \"%s\": %w", opts.kubeContext, err)
	}

	csdpToken := cfConfig.GetCurrentContext().Token
	k, nameSuffix := createAddClusterKustomization(ingressUrl, opts.clusterName, server, csdpToken, *runtime.RuntimeVersion)

	manifests, err := kustutil.BuildKustomization(k)
	if err != nil {
		return fmt.Errorf("failed building kustomization: %w", err)
	}

	if opts.dryRun {
		fmt.Println(string(manifests))
		return nil
	}

	err = opts.kubeFactory.Apply(ctx, manifests)
	if err != nil {
		return fmt.Errorf("failed applying manifests to cluster: %w", err)
	}

	return kubeutil.WaitForJob(ctx, opts.kubeFactory, "kube-system", fmt.Sprintf("%s%s", store.Get().AddClusterJobName, nameSuffix))
}

func setClusterName(ctx context.Context, opts *ClusterAddOptions) error {
	if opts.clusterName != "" {
		return validateClusterName(opts.clusterName)
	}

	var err error
	sanitizedName := sanitizeClusterName(opts.kubeContext)
	opts.clusterName, err = ensureNoClusterNameDuplicates(ctx, sanitizedName, opts.runtimeName)

	return err
}

func validateClusterName(name string) error {
	maxDNSNameLength := 253
	if len(name) > maxDNSNameLength {
		return fmt.Errorf("cluster name can contain no more than 253 characters")
	}

	match, err := regexp.MatchString("^[a-z\\d]([-a-z\\d\\.]{0,251}[a-z\\d])?$", name)
	if err != nil {
		return err
	}

	if !match {
		return fmt.Errorf("cluster name must be according to k8s resource naming rules")
	}

	return nil
}

// copied from https://github.com/argoproj/argo-cd/blob/master/applicationset/generators/cluster.go#L214
func sanitizeClusterName(name string) string {
	invalidDNSNameChars := regexp.MustCompile("[^-a-z0-9.]")
	maxDNSNameLength := 253

	name = strings.ToLower(name)
	name = invalidDNSNameChars.ReplaceAllString(name, "-")
	// saving space for 2 chars in case a cluster with the sanitized name already exists 
	if len(name) > (maxDNSNameLength - 2) {
		name = name[:(maxDNSNameLength - 2)]
	}

	return strings.Trim(name, "-.")
}

func ensureNoClusterNameDuplicates(ctx context.Context, name string, runtimeName string) (string, error) {
	clusters, err := cfConfig.NewClient().V2().Cluster().List(ctx, runtimeName)
	if err != nil {
		return "", fmt.Errorf("failed to get clusters list: %w", err)
	}
	
	suffix := getSuffixToClusterName(clusters, name, name, 0)
	if suffix != 0 {
		return fmt.Sprintf("%s-%d", name, suffix), nil
	}

	return name, nil
}

func getSuffixToClusterName(clusters []model.Cluster, name string, tempName string, counter int) int {
	for _, cluster := range clusters {
		if cluster.Metadata.Name == tempName {
			counter++
			tempName = fmt.Sprintf("%s-%d", name, counter)
			counter = getSuffixToClusterName(clusters, name, tempName, counter)
			break
		}
	}

	return counter
}

func createAddClusterKustomization(ingressUrl, contextName, server, csdpToken, version string) (*kusttypes.Kustomization, string) {
	nameSuffix := getClusterResourcesNameSuffix()
	resourceUrl := store.AddClusterDefURL
	if strings.HasPrefix(resourceUrl, "http") {
		resourceUrl = fmt.Sprintf("%s?ref=v%s", resourceUrl, version)
	}

	k := &kusttypes.Kustomization{
		ConfigMapGenerator: []kusttypes.ConfigMapArgs{
			{
				GeneratorArgs: kusttypes.GeneratorArgs{
					Namespace: "kube-system",
					Name:      "csdp-add-cluster-cm",
					Behavior:  "merge",
					KvPairSources: kusttypes.KvPairSources{
						LiteralSources: []string{
							fmt.Sprintf("ingressUrl=" + ingressUrl),
							fmt.Sprintf("contextName=" + contextName),
							fmt.Sprintf("server=" + server),
						},
					},
				},
			},
		},
		SecretGenerator: []kusttypes.SecretArgs{
			{
				GeneratorArgs: kusttypes.GeneratorArgs{
					Namespace: "kube-system",
					Name:      "csdp-add-cluster-secret",
					Behavior:  "merge",
					KvPairSources: kusttypes.KvPairSources{
						LiteralSources: []string{
							fmt.Sprintf("csdpToken=" + csdpToken),
						},
					},
				},
			},
		},
		Resources: []string{
			resourceUrl,
		},
		NameSuffix: nameSuffix,
	}
	k.FixKustomizationPostUnmarshalling()
	util.Die(k.FixKustomizationPreMarshalling())
	return k, nameSuffix
}

func getClusterResourcesNameSuffix() string {
	now := time.Now()
	return fmt.Sprintf("-%d", now.UnixMilli())
}

func newClusterRemoveCommand() *cobra.Command {
	var opts ClusterRemoveOptions

	cmd := &cobra.Command{
		Use:     "remove [RUNTIME_NAME]",
		Short:   "Removes a cluster from a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster remove my-runtime --server-url https://<some-hash>.gr7.us-east-1.eks.amazonaws.com`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()

			opts.runtimeName, err = ensureRuntimeName(ctx, args, true)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterRemove(cmd.Context(), &opts)
		},
	}

	cmd.Flags().StringVar(&opts.server, "server-url", "", "The cluster's server url")
	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "server-url"))

	return cmd
}

func runClusterRemove(ctx context.Context, opts *ClusterRemoveOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.runtimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.AppProxyClusters().Delete(ctx, opts.server, opts.runtimeName)
	if err != nil {
		return fmt.Errorf("failed to remove cluster: %w", err)
	}

	log.G(ctx).Info("cluster was removed successfully")

	return nil
}

func newClusterListCommand() *cobra.Command {
	runtimeName := ""

	cmd := &cobra.Command{
		Use:     "list [RUNTIME_NAME]",
		Short:   "List all the clusters of a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster list my-runtime`),
		PreRun: func(_ *cobra.Command, args []string) {
			if len(args) == 1 {
				runtimeName = args[0]
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterList(cmd.Context(), runtimeName)
		},
	}

	return cmd
}

func runClusterList(ctx context.Context, runtimeName string) error {
	clusters, err := cfConfig.NewClient().V2().Cluster().List(ctx, runtimeName)
	if err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
	}

	if len(clusters) == 0 {
		log.G(ctx).Info("No clusters were found")
		return nil
	}

	sort.SliceStable(clusters, func(i, j int) bool {
		c1 := clusters[i]
		if c1.Metadata.Name == "in-cluster" {
			return true
		}

		c2 := clusters[j]
		if c2.Metadata.Name == "in-cluster" {
			return false
		}

		return c1.Metadata.Name < c2.Metadata.Name
	})

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	if runtimeName == "" {
		_, err = fmt.Fprint(tb, "RUNTIME\t")
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintln(tb, "SERVER\tNAME\tVERSION\tSTATUS\tMESSAGE")
	if err != nil {
		return err
	}

	for _, c := range clusters {
		server := c.Server
		if len(c.Namespaces) > 0 {
			server = fmt.Sprintf("%s (%d namespaces)", c.Server, len(c.Namespaces))
		}

		version := ""
		if c.Info.ServerVersion != nil {
			version = *c.Info.ServerVersion
		}

		message := ""
		if c.Info.ConnectionState.Message != nil {
			message = *c.Info.ConnectionState.Message
		}

		if runtimeName == "" {
			_, err = fmt.Fprintf(tb, "%s\t", c.Metadata.Runtime)
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			server,
			c.Metadata.Name,
			version,
			c.Info.ConnectionState.Status,
			message,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func newClusterCreateArgoRolloutsCommand() *cobra.Command {
	var opts ClusterCreateArgoRolloutsOptions

	cmd := &cobra.Command{
		Use:     "create-argo-rollouts [RUNTIME_NAME]",
		Short:   "creates argo-rollouts component on the target cluster",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster create-argo-rollouts my-runtime --server-url https://<some-hash>.gr7.us-east-1.eks.amazonaws.com --namespace managed-ns`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			opts.runtimeName, err = ensureRuntimeName(cmd.Context(), args, true)
			return err
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreateArgoRollouts(cmd.Context(), &opts)
		},
	}

	cmd.Flags().StringVar(&opts.server, "server-url", "", "The cluster's server url")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "", "Path to the kubeconfig file")
	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "server-url"))
	util.Die(cobra.MarkFlagRequired(cmd.Flags(), "namespace"))

	return cmd
}

func runCreateArgoRollouts(ctx context.Context, opts *ClusterCreateArgoRolloutsOptions) error {
	appProxy, err := cfConfig.NewClient().AppProxy(ctx, opts.runtimeName, store.Get().InsecureIngressHost)
	if err != nil {
		return err
	}

	err = appProxy.AppProxyClusters().CreateArgoRollouts(ctx, opts.server, opts.namespace)
	if err != nil {
		return fmt.Errorf("failed to create argo-rollouts on \"%s'\": %w", opts.server, err)
	}

	log.G(ctx).Infof("created argo-rollouts component on \"%s\"", opts.server)

	return nil
}
