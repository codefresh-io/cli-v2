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

package openshift

import (
	"context"
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"
	kubeutil "github.com/codefresh-io/cli-v2/pkg/util/kube"

	"github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/argoproj-labs/argocd-autopilot/pkg/kube"
	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	ocsecurityv1 "github.com/openshift/api/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OpenshiftOptions struct {
	KubeFactory      kube.Factory
	RuntimeName      string
	RuntimeNamespace string
	InsCloneOpts     *git.CloneOptions
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

	scc := ocsecurityv1.SecurityContextConstraints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityContextConstraints",
			APIVersion: "security.openshift.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.RuntimeNamespace,
			Name:      store.Get().SccName,
		},
		AllowPrivilegedContainer: false,
		RunAsUser: ocsecurityv1.RunAsUserStrategyOptions{
			Type: ocsecurityv1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: ocsecurityv1.SELinuxContextStrategyOptions{
			Type: ocsecurityv1.SELinuxStrategyRunAsAny,
		},
		Users: getServiceAccountsList(opts.RuntimeName),
		// This is required to take precedence over the default SCC's
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
