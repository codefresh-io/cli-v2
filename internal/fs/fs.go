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

package fs

import (
	"fmt"
	"io"

	"github.com/codefresh-io/cli-v2/internal/util"

	"github.com/ghodss/yaml"
	"github.com/go-git/go-billy/v5"
)

//go:generate mockgen -destination=./mocks/fs.go -package=mocks -source=./fs.go FS

type FS interface {
	billy.Filesystem

	// ReadYamls reads the file data as yaml into o
	ReadYamls(filename string, o ...interface{}) error
}

type fsimpl struct {
	billy.Filesystem
}

func Create(bfs billy.Filesystem) FS {
	return &fsimpl{bfs}
}

func (fs *fsimpl) ReadYamls(filename string, o ...interface{}) error {
	data, err := readFile(fs, filename)
	if err != nil {
		return err
	}

	yamls := util.SplitManifests(data)
	if len(yamls) < len(o) {
		return fmt.Errorf("expected at least %d manifests when reading '%s'", len(o), filename)
	}

	for i, e := range o {
		if e == nil {
			continue
		}

		err = yaml.Unmarshal(yamls[i], e)
		if err != nil {
			return err
		}
	}

	return nil
}

func readFile(fs FS, filename string) ([]byte, error) {
	f, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}
