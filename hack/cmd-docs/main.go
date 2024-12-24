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

package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefresh-io/cli-v2/cmd/commands"

	"github.com/spf13/cobra/doc"
)

const (
	outputDir = "./docs/commands"
	home      = "/home/user"
)

var orgHome = os.Getenv("HOME")

func main() {
	log.Printf("org home: %s", orgHome)
	log.Printf("new home: %s", home)

	if err := doc.GenMarkdownTree(commands.NewRoot(), outputDir); err != nil {
		log.Fatal(fmt.Errorf("failed generating markdown tree: %w", err))
	}

	if err := replaceHome(); err != nil {
		log.Fatal(fmt.Errorf("failed replacing home: %w", err))
	}
}

func replaceHome() error {
	files, err := fs.Glob(os.DirFS(outputDir), "*.md")
	if err != nil {
		return fmt.Errorf("failed globbing files: %w", err)
	}

	for _, fname := range files {
		fname = filepath.Join(outputDir, fname)
		data, err := os.ReadFile(fname)
		if err != nil {
			return fmt.Errorf("failed reading file: %w", err)
		}

		datastr := string(data)
		newstr := strings.ReplaceAll(datastr, orgHome, home)

		if datastr == newstr {
			continue
		}

		log.Printf("replaced home at: %s", fname)

		err = os.WriteFile(fname, []byte(newstr), 0422)
		if err != nil {
			return fmt.Errorf("failed writing file: %w", err)
		}
	}
	return nil
}
