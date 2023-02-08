// Copyright 2023 The Codefresh Authors.
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
	"github.com/ghodss/yaml"

	"github.com/Masterminds/semver/v3"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	kusttypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/resid"
)

type (
	ClusterAddOptions struct {
		runtimeName       string
		clusterName       string
		kubeContext       string
		kubeconfig        string
		systemNamespace   string
		annotations       map[string]string
		labels            map[string]string
		tag               string
		dryRun            bool
		skipTLSValidation bool
		kubeFactory       kube.Factory
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

var (
	minAddClusterSupportedVersion       = semver.MustParse("0.0.283")
	minAddClusterLabelsSupportedVersion = semver.MustParse("0.0.462")

	serviceAccountGVK = resid.Gvk{
		Version: "v1",
		Kind:    "ServiceAccount",
	}
	jobGVK = resid.Gvk{
		Group:   "batch",
		Version: "v1",
		Kind:    "Job",
	}
	clusterRoleBindinGVK = resid.Gvk{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRoleBinding",
	}
)

func NewClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
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
	var (
		opts ClusterAddOptions
	)

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

			return setClusterName(cmd.Context(), &opts)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterAdd(cmd.Context(), &opts)
		},
	}

	cmd.Flags().StringVar(&opts.clusterName, "name", "", "Name of the cluster. If omitted, will use the context name")
	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", "kube-system", "Use different system namespace (default \"kube-system\")")
	cmd.Flags().StringToStringVar(&opts.annotations, "annotations", nil, "Set metadata annotations (e.g. --annotation key=value)")
	cmd.Flags().StringToStringVar(&opts.labels, "labels", nil, "Set metadata labels (e.g. --label key=value)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "")
	cmd.Flags().BoolVar(&opts.skipTLSValidation, "skip-tls-validation", false, "Set true to skip TLS validation for cluster domain")
	cmd.Flags().StringVar(&opts.tag, "tag", "", "[dev only] - use a specific tag of the csdp-add-cluster image")

	util.Die(cmd.Flags().MarkHidden("tag"))
	opts.kubeFactory = kube.AddFlags(cmd.Flags())

	return cmd
}

func runClusterAdd(ctx context.Context, opts *ClusterAddOptions) error {
	runtime, err := getRuntime(ctx, opts.runtimeName)
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

	if (len(opts.annotations) > 0 || len(opts.labels) > 0) && version.LessThan(minAddClusterLabelsSupportedVersion) {
		return fmt.Errorf("runtime \"%s\" does not support adding clusters with annotations or labels. Minimal required version is %s", opts.runtimeName, minAddClusterLabelsSupportedVersion)
	}

	if runtime.IngressHost == nil {
		return fmt.Errorf("runtime \"%s\" is missing an ingress URL", opts.runtimeName)
	}

	ingressUrl := *runtime.IngressHost
	server, err := util.KubeServerByContextName(opts.kubeContext, opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("failed getting server for context \"%s\": %w", opts.kubeContext, err)
	}

	log.G(ctx).Info("Building \"add-cluster\" manifests")

	csdpToken := cfConfig.GetCurrentContext().Token
	manifests, nameSuffix, err := createAddClusterManifests(opts, ingressUrl, server, csdpToken, version.String())
	if err != nil {
		return fmt.Errorf("failed getting add-cluster resources: %w", err)
	}

	if opts.dryRun {
		fmt.Println(string(manifests))
		return nil
	}

	err = opts.kubeFactory.Apply(ctx, manifests)
	if err != nil {
		return fmt.Errorf("failed applying manifests to cluster: %w", err)
	}

	jobName := strings.TrimSuffix(store.Get().AddClusterJobName, "-") + nameSuffix

	err = kubeutil.WaitForJob(ctx, opts.kubeFactory, opts.systemNamespace, jobName)
	if err != nil {
		return err
	}

	fmt.Printf("%vcluster %s was added successfully to runtime %s%v\n", GREEN, opts.clusterName, opts.runtimeName, COLOR_RESET)
	return nil
}

func setClusterName(ctx context.Context, opts *ClusterAddOptions) error {
	if opts.clusterName != "" {
		return validateClusterName(opts.clusterName)
	}

	var err error
	sanitizedName, err := sanitizeClusterName(opts.kubeContext)
	if err != nil {
		return err
	}

	opts.clusterName, err = ensureNoClusterNameDuplicates(ctx, sanitizedName, opts.runtimeName)

	return err
}

func validateClusterName(name string) error {
	maxNameLength := 63
	if len(name) > maxNameLength {
		return fmt.Errorf("cluster name can contain no more than 63 characters")
	}

	match, err := regexp.MatchString("^[a-z]([-a-z\\d]{0,61}[a-z\\d])?$", name)
	if err != nil {
		return err
	}

	if !match {
		return fmt.Errorf("cluster name must be according to k8s RFC 1035 label names rules")
	}

	return nil
}

// partially copied from https://github.com/argoproj/argo-cd/blob/master/applicationset/generators/cluster.go#L214
func sanitizeClusterName(name string) (string, error) {
	nameKeeper := name
	invalidNameChars := regexp.MustCompile("[^-a-z0-9]")
	maxNameLength := 63

	name = strings.ToLower(name)
	name = invalidNameChars.ReplaceAllString(name, "-")
	// saving space for 2 chars in case a cluster with the sanitized name already exists
	if len(name) > (maxNameLength - 2) {
		name = name[:(maxNameLength - 2)]
	}

	name = strings.Trim(name, "-.")

	beginsWithNum := regexp.MustCompile(`^\d+`)
	name = beginsWithNum.ReplaceAllString(name, "")

	if name == "" {
		return "", fmt.Errorf("failed sanitizing cluster name \"%s\". please use --name flag manually", nameKeeper)
	}

	return name, nil
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

func createAddClusterManifests(opts *ClusterAddOptions, ingressUrl, server, csdpToken, version string) ([]byte, string, error) {
	nameSuffix := getClusterResourcesNameSuffix()
	resourceUrl := store.AddClusterDefURL
	if strings.HasPrefix(resourceUrl, "http") {
		ref := version
		if opts.tag != "" {
			ref = opts.tag
		}

		resourceUrl = fmt.Sprintf("%s?ref=%s", resourceUrl, ref)
	}

	k := &kusttypes.Kustomization{
		Namespace: opts.systemNamespace,
		Patches: []kusttypes.Patch{{
			Patch: fmt.Sprintf("[{\"op\": \"replace\", \"path\": \"/subjects/0/namespace\", \"value\": \"%s\"}]", opts.systemNamespace),
			Target: &kusttypes.Selector{
				ResId: resid.ResId{Gvk: clusterRoleBindinGVK, Name: "argocd-manager-role-binding"},
			},
		}},
		ConfigMapGenerator: []kusttypes.ConfigMapArgs{
			{
				GeneratorArgs: kusttypes.GeneratorArgs{
					Namespace: "kube-system",
					Name:      "csdp-add-cluster-cm",
					Behavior:  "merge",
					KvPairSources: kusttypes.KvPairSources{
						LiteralSources: []string{
							fmt.Sprintf("ingressUrl=" + ingressUrl),
							fmt.Sprintf("contextName=" + opts.clusterName),
							fmt.Sprintf("server=" + server),
							fmt.Sprintf("skipTLSValidation=%v", opts.skipTLSValidation),
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
		Replacements: []kusttypes.ReplacementField{
			{
				Replacement: kusttypes.Replacement{
					Source: &kusttypes.SourceSelector{
						ResId: resid.ResId{
							Gvk:  serviceAccountGVK,
							Name: "argocd-manager",
						},
						FieldPath: "metadata.name",
					},
					Targets: []*kusttypes.TargetSelector{
						{
							Select: &kusttypes.Selector{
								ResId: resid.ResId{
									Gvk:  jobGVK,
									Name: "csdp-add-cluster-job",
								},
							},
							FieldPaths: []string{
								"spec.template.spec.serviceAccount",
							},
						},
						{
							Select: &kusttypes.Selector{
								ResId: resid.ResId{
									Gvk:  clusterRoleBindinGVK,
									Name: "argocd-manager-role-binding",
								},
							},
							FieldPaths: []string{
								"subjects.[name=argocd-manager].name",
							},
						},
					},
				},
			},
		},
	}

	if len(opts.annotations) > 0 {
		annotationsStr, err := mapToYaml(opts.annotations)
		if err != nil {
			return nil, "", fmt.Errorf("failed encoding annotations: %w", err)
		}

		k.ConfigMapGenerator[0].KvPairSources.LiteralSources = append(k.ConfigMapGenerator[0].KvPairSources.LiteralSources, fmt.Sprintf("annotations="+annotationsStr))
	}

	if len(opts.labels) > 0 {
		labelsStr, err := mapToYaml(opts.labels)
		if err != nil {
			return nil, "", fmt.Errorf("failed encoding labels: %w", err)
		}

		k.ConfigMapGenerator[0].KvPairSources.LiteralSources = append(k.ConfigMapGenerator[0].KvPairSources.LiteralSources, fmt.Sprintf("labels="+labelsStr))
	}

	if opts.tag != "" {
		k.Images = []kusttypes.Image{
			{
				Name:   "quay.io/codefresh/csdp-add-cluster",
				NewTag: opts.tag,
			},
		}
	}

	k.FixKustomizationPostUnmarshalling()
	util.Die(k.FixKustomizationPreMarshalling())

	manifests, err := kustutil.BuildKustomization(k)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build kustomization: %w", err)
	}

	return manifests, nameSuffix, nil
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			// this is a temp solution for too short timeout when removing a cluster
			// (on app-proxy it is waiting for the isc to finalize which can take a while)
			// this should be removed after implementing a scalable solution (CR-13259)
			die(cmd.Flags().Set("request-timeout", "120s"))
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

func mapToYaml(m map[string]string) (string, error) {
	data, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
