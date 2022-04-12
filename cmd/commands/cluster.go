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
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	cdutil "github.com/codefresh-io/cli-v2/pkg/util/cd"
	kustutil "github.com/codefresh-io/cli-v2/pkg/util/kust"

	"github.com/Masterminds/semver/v3"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	kusttypes "sigs.k8s.io/kustomize/api/types"
)

type (
	ClusterAddOptions struct {
		runtimeName string
		kubeContext string
		kubeconfig  string
		dryRun      bool
		kubeFactory kube.Factory
	}

	ClusterRemoveOptions struct {
		server      string
		runtimeName string
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

	cmd.AddCommand(NewClusterAddCommand())
	cmd.AddCommand(NewClusterRemoveCommand())
	cmd.AddCommand(NewClusterListCommand())

	return cmd
}

func NewClusterAddCommand() *cobra.Command {
	var (
		opts ClusterAddOptions
		err  error
	)

	cmd := &cobra.Command{
		Use:     "add RUNTIME_NAME",
		Short:   "Add a cluster to a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster add my-runtime --context my-context`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()

			opts.runtimeName, err = ensureRuntimeName(ctx, args)
			if err != nil {
				return err
			}

			opts.kubeContext, err = ensureKubeContextName(cmd.Flag("context"), cmd.Flag("kubeconfig"))
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterAdd(cmd.Context(), &opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "")
	opts.kubeFactory = kube.AddFlags(cmd.Flags())
	die(err)

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

	if runtime.IngressHost == "" {
		return fmt.Errorf("runtime \"%s\" is missing an ingress URL", opts.runtimeName)
	}

	ingressUrl := runtime.IngressHost
	server, err := util.KubeServerByContextName(opts.kubeContext, opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("failed getting server for context \"%s\": %w", opts.kubeContext, err)
	}

	csdpToken := cfConfig.GetCurrentContext().Token
	k := createAddClusterKustomization(ingressUrl, opts.kubeContext, server, csdpToken, *runtime.RuntimeVersion)

	manifests, err := kustutil.BuildKustomization(k)
	if err != nil {
		return fmt.Errorf("failed building kustomization:%w", err)
	}

	if opts.dryRun {
		fmt.Println(string(manifests))
		return nil
	}

	return opts.kubeFactory.Apply(ctx, manifests)
}

func createAddClusterKustomization(ingressUrl, contextName, server, csdpToken, version string) *kusttypes.Kustomization {
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
	}
	k.FixKustomizationPostUnmarshalling()
	util.Die(k.FixKustomizationPreMarshalling())
	return k
}

func NewClusterRemoveCommand() *cobra.Command {
	var (
		opts ClusterRemoveOptions
	)

	cmd := &cobra.Command{
		Use:     "remove RUNTIME_NAME",
		Short:   "Removes a cluster from a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster remove my-runtime --server-url my-server-url`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			ctx := cmd.Context()

			opts.runtimeName, err = ensureRuntimeName(ctx, args)
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

	err = appProxy.AppProxyClusters().RemoveCluster(ctx, opts.server, opts.runtimeName)
	if err != nil {
		return fmt.Errorf("failed to remove cluster: %w", err)
	}

	log.G(ctx).Info("cluster was removed successfully")

	return nil
}

func NewClusterListCommand() *cobra.Command {
	var runtimeName string
	var kubeconfig string

	cmd := &cobra.Command{
		Use:     "list RUNTIME_NAME",
		Short:   "List all the clusters of a given runtime",
		Args:    cobra.MaximumNArgs(1),
		Example: util.Doc(`<BIN> cluster list my-runtime`),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			runtimeName, err = ensureRuntimeName(cmd.Context(), args)
			return err
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterList(cmd.Context(), runtimeName, kubeconfig)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")

	return cmd
}

func runClusterList(ctx context.Context, runtimeName, kubeconfig string) error {
	runtime, err := cfConfig.NewClient().V2().Runtime().Get(ctx, runtimeName)
	if err != nil {
		return err
	}

	kubeContext, err := util.KubeContextNameByServer(*runtime.Cluster, kubeconfig)
	if err != nil {
		return fmt.Errorf("failed getting context for \"%s\": %w", *runtime.Cluster, err)
	}

	clusters, err := cdutil.GetClusterList(ctx, kubeContext, *runtime.Metadata.Namespace, false)
	if err != nil {
		return err
	}

	if len(clusters.Items) == 0 {
		log.G(ctx).Info("No clusters were found")
		return nil
	}

	tb := ansiterm.NewTabWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, err = fmt.Fprintln(tb, "SERVER\tNAME\tVERSION\tSTATUS\tMESSAGE")
	if err != nil {
		return err
	}

	for _, c := range clusters.Items {
		server := c.Server
		if len(c.Namespaces) > 0 {
			server = fmt.Sprintf("%s (%d namespaces)", c.Server, len(c.Namespaces))
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
			server,
			c.Name,
			c.ServerVersion,
			c.ConnectionState.Status,
			c.ConnectionState.Message,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}
