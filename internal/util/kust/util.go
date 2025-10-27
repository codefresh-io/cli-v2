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

package util

import (
	"os"
	"path/filepath"

	"sigs.k8s.io/kustomize/api/krusty"
	kusttypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
)

func BuildKustomization(k *kusttypes.Kustomization) ([]byte, error) {
	td, err := os.MkdirTemp("", "csdp-add-cluster")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(td) }()

	kyaml, err := yaml.Marshal(k)
	if err != nil {
		return nil, err
	}

	kustomizationPath := filepath.Join(td, "kustomization.yaml")
	if err = os.WriteFile(kustomizationPath, kyaml, 0400); err != nil {
		return nil, err
	}

	opts := krusty.MakeDefaultOptions()
	kust := krusty.MakeKustomizer(opts)
	fs := filesys.MakeFsOnDisk()
	res, err := kust.Run(fs, td)
	if err != nil {
		return nil, err
	}

	return res.AsYaml()
}
