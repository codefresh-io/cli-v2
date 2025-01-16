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

// Copyright 2024 The Codefresh Authors.
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
	"os"
	"path/filepath"

	apfs "github.com/argoproj-labs/argocd-autopilot/pkg/fs"
	"github.com/ghodss/yaml"
	"sigs.k8s.io/kustomize/api/krusty"
	kusttypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

var KUSTOMOZATION_FILE_NAME = "kustomization.yaml"

func ReadKustomization(fs apfs.FS, directory string) (*kusttypes.Kustomization, error) {
	fileName := fs.Join(directory, KUSTOMOZATION_FILE_NAME)
	kust := &kusttypes.Kustomization{}
	if err := fs.ReadYamls(fileName, kust); err != nil {
		return nil, fmt.Errorf("failed reading kustomization from \"%s\": %w", fileName, err)
	}

	return kust, nil
}

func ReplaceResource(kust *kusttypes.Kustomization, fromURL, toURL string) error {
	found := false
	for i, res := range kust.Resources {
		if res == fromURL {
			kust.Resources[i] = toURL
			found = true
			break
		}
	}

	if !found {
		if len(kust.Resources) == 1 {
			kust.Resources[0] = toURL
		} else {
			return fmt.Errorf("base kustomization does not contain expected resource \"%s\"", fromURL)
		}
	}

	return nil
}

func WriteKustomization(fs apfs.FS, kust *kusttypes.Kustomization, directory string) error {
	fileName := fs.Join(directory, KUSTOMOZATION_FILE_NAME)
	return fs.WriteYamls(fileName, kust)
}

func BuildKustomization(k *kusttypes.Kustomization) ([]byte, error) {
	td, err := os.MkdirTemp("", "csdp-add-cluster")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)

	kyaml, err := yaml.Marshal(k)
	if err != nil {
		return nil, err
	}

	kustomizationPath := filepath.Join(td, "kustomization.yaml")
	if err = os.WriteFile(kustomizationPath, kyaml, 0400); err != nil {
		return nil, err
	}

	opts := krusty.MakeDefaultOptions()
	opts.Reorder = krusty.ReorderOptionLegacy
	kust := krusty.MakeKustomizer(opts)
	fs := filesys.MakeFsOnDisk()
	res, err := kust.Run(fs, td)
	if err != nil {
		return nil, err
	}

	return res.AsYaml()
}
