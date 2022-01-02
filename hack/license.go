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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var (
		licenseFile string
		year        int
	)

	flag.StringVar(&licenseFile, "license", "", "license file path")
	flag.IntVar(&year, "year", 0, "year")
	flag.Parse()

	if licenseFile == "" {
		panic("--license required")
	}

	if year <= 0 {
		panic("--year positive int required")
	}

	d, err := ioutil.ReadFile(licenseFile)
	die(err)

	license := string(d)

	license = strings.ReplaceAll(license, "YEAR", fmt.Sprintf("%d", year))

	die(filepath.Walk(flag.Arg(0), func(path string, info os.FileInfo, err error) error {
		die(err)
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		f, err := os.OpenFile(path, os.O_RDWR, info.Mode())
		die(err)
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		die(err)

		s := string(data)

		if strings.HasPrefix(strings.TrimSpace(s), strings.TrimSpace(license)) {
			return nil
		}

		log.Print(path)

		s = license + s
		_, err = f.WriteAt([]byte(s), 0)
		die(err)
		return nil
	}))
}

func die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
