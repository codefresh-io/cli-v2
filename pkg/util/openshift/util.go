package openshift

import (
	"context"
	"fmt"

	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"
	ocSecurityV1 "github.com/openshift/api/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OpenshiftOptions struct {
	KubeFactory  kube.Factory
	RuntimeName  string
	InsCloneOpts *git.CloneOptions
}

const openshiftNs = "openshift"

func PrepareOpenshiftCluster(ctx context.Context, opts *OpenshiftOptions) error {
	isOpenshift, err := isOpenshiftCluster(ctx, opts.KubeFactory)
	if err != nil {
		return err
	}

	if !isOpenshift {
		return nil
	}

	err = createScc(ctx, opts)
	if err != nil {
		return err
	}

	return nil
}

func isOpenshiftCluster(ctx context.Context, kubeFactory kube.Factory) (bool, error) {
	exists, err := kubeutil.CheckNamespaceExists(ctx, openshiftNs, kubeFactory)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}

	log.G().Info("Running on an Openshift cluster")
	return true, nil
}

func createScc(ctx context.Context, opts *OpenshiftOptions) error {
	r, fs, err := opts.InsCloneOpts.GetRepo(ctx)
	if err != nil {
		return err
	}
	sccPriority := int32(15)

	scc := ocSecurityV1.SecurityContextConstraints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityContextConstraints",
			APIVersion: "security.openshift.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.RuntimeName,
			Name:      store.Get().SccName,
		},
		AllowPrivilegedContainer: false,
		RunAsUser: ocSecurityV1.RunAsUserStrategyOptions{
			Type: ocSecurityV1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: ocSecurityV1.SELinuxContextStrategyOptions{
			Type: ocSecurityV1.SELinuxStrategyRunAsAny,
		},
		Users:    getServiceAccountsList(opts.RuntimeName),
		Priority: &sccPriority,
	}

	clusterResourcesDir := fs.Join(apstore.Default.BootsrtrapDir, apstore.Default.ClusterResourcesDir, "in-cluster")

	if err = fs.WriteYamls(fs.Join(clusterResourcesDir, "scc.yaml"), scc); err != nil {
		return err
	}

	log.G(ctx).Info("Pushing scc manifest")

	return apu.PushWithMessage(ctx, r, "Created scc")
}

func getServiceAccountsList(runtimeName string) []string {
	return []string{
		fmt.Sprintf("system:serviceaccount:%s:argo-events-sa", runtimeName),
		fmt.Sprintf("system:serviceaccount:%s:argo-events-webhook-sa", runtimeName),
		fmt.Sprintf("system:serviceaccount:%s:argo-server", runtimeName),
		fmt.Sprintf("system:serviceaccount:%s:argocd-redis", runtimeName),
		fmt.Sprintf("system:serviceaccount:%s:cap-app-proxy", runtimeName),
	}
}
