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

// Copyright 2021 The Codefresh Authors.
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

package util

import (
	"fmt"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kustid "sigs.k8s.io/kustomize/api/resid"
	kusttypes "sigs.k8s.io/kustomize/api/types"
)

type (
	CreateAgentOptions struct {
		Name      string
		Namespace string
	}
)

func addPatch(patches []kusttypes.Patch, gvk kustid.Gvk, patch string) []kusttypes.Patch {
	return append(patches, kusttypes.Patch{
		Target: &kusttypes.Selector{
			KrmId: kusttypes.KrmId{
				Gvk: gvk,
			},
		},
		Patch: patch,
	})
}

func CreateAgentResourceKustomize(options *CreateAgentOptions) kusttypes.Kustomization {
	kust := kusttypes.Kustomization{
		TypeMeta: kusttypes.TypeMeta{
			APIVersion: kusttypes.KustomizationVersion,
			Kind:       kusttypes.KustomizationKind,
		},
	}

	namespaceReplacement := fmt.Sprintf(`- op: replace
  path: /metadata/namespace
  value: %s`, options.Namespace)

	crbNamespaceReplacement := fmt.Sprintf(`- op: replace
  path: /subjects/0/namespace
  value: %s`, options.Namespace)

	hostReplacement := fmt.Sprintf(`- op: replace
  path: /data/host
  value: "http://argocd-server.%s.svc.cluster.local"`, options.Namespace)

	integrationReplacement := fmt.Sprintf(`- op: replace
  path: /data/integration
  value: argocd-%s`, options.Name)

	kust.Resources = append(kust.Resources, "https://raw.githubusercontent.com/codefresh-io/cli-v2/main/manifests/argo-agent/agent.yaml")

	kust.Patches = addPatch(kust.Patches, kustid.Gvk{
		Group:   appsv1.SchemeGroupVersion.Group,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	}, namespaceReplacement)

	kust.Patches = addPatch(kust.Patches, kustid.Gvk{
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "ServiceAccount",
	}, namespaceReplacement)

	kust.Patches = addPatch(kust.Patches, kustid.Gvk{
		Group:   rbacv1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "ClusterRoleBinding",
	}, crbNamespaceReplacement)

	kust.Patches = addPatch(kust.Patches, kustid.Gvk{
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "ConfigMap",
	}, hostReplacement)

	kust.Patches = addPatch(kust.Patches, kustid.Gvk{
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "ConfigMap",
	}, integrationReplacement)

	return kust
}
