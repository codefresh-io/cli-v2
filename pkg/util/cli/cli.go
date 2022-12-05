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

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"go/build"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/spf13/cobra"
)

// we don't want to slow down the cli so it is noticable
// so you get 2 seconds to check the version, which should
// be enough for most configurations
var getVersionTimeout = time.Second * 2

const (
	color           = "\u001b[38;5;220m"
	clearColor      = "\033[0m"
	expectedBinFile = "cf-%s-%s"

	SkipVersionCheck = "skip-version-check"
)

func UpgradeCLIToVersion(ctx context.Context, version, output string) error {
	if version != "" {
		_, err := semver.NewVersion(version)
		if err != nil {
			return fmt.Errorf("failed to parse specified version '%s': %w", version, err)
		}
	} else {
		latestVersion, err := getLatestCliVersion(ctx)
		if err != nil {
			return fmt.Errorf("failed to get latest version: %w", err)
		}
		version = latestVersion.String()
	}

	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	cliDownloadLink := buildDownloadLink(version)

	binaryFile, err := downloadAndExtract(ctx, cliDownloadLink, version)
	if err != nil {
		return fmt.Errorf("failed to get cli binary: %w", err)
	}

	curBinPath, err := getCurrentBinaryPath()
	if err != nil {
		return fmt.Errorf("failed to get current binary path: %w", err)
	}

	if output == "" {
		output = curBinPath
	}

	log.G(ctx).Debugf("copying from '%s' to '%s'", binaryFile, output)
	log.G(ctx).Info("Copying...")
	if err := os.Rename(binaryFile, output); err != nil {
		return fmt.Errorf("failed to copy new binary from '%s' to '%s': %w", binaryFile, output, err)
	}

	log.G(ctx).Info("Done!")

	if curBinPath != output {
		log.G(ctx).Infof("New binary saved to: %s", output)
	}

	return nil
}

func AddCLIVersionCheck(cmd *cobra.Command) {
	var skipCheck bool

	initFunc := func(cmd *cobra.Command) {
		orgPreRunE := cmd.PreRunE

		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if !skipCheck && !hasSkipCheckAnnotation(cmd) {
				checkCliVersion(cmd.Context())
			}

			if orgPreRunE != nil {
				return orgPreRunE(cmd, args)
			}
			if cmd.PreRun != nil {
				cmd.PreRun(cmd, args)
			}

			return nil
		}
	}

	cobra.OnInitialize(func() { initCommands(cmd, initFunc) })

	cmd.PersistentFlags().BoolVar(&skipCheck, "skip-version-check", false, "Disable the automatic CLI version check")
}

func buildDownloadLink(version string) string {
	return fmt.Sprintf(store.Get().CLIDownloadTemplate,
		version, build.Default.GOOS, build.Default.GOARCH)
}

func initCommands(cmd *cobra.Command, initFunc func(*cobra.Command)) {
	initFunc(cmd)

	for _, subCommand := range cmd.Commands() {
		if subCommand.HasSubCommands() {
			initCommands(subCommand, initFunc)
		} else {
			initFunc(subCommand)
		}
	}
}

func checkCliVersion(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, getVersionTimeout)
	defer cancel()

	log.G(ctx).Debug("Checking cli version...")

	v, err := getLatestCliVersion(ctx)
	if err != nil {
		log.G(ctx).Debugf("failed to get latest cli version: %v", err.Error())
		return
	}

	curV := store.Get().Version.Version

	if v.Compare(curV) <= 0 {
		return
	}

	msg := spaceAccordingly(`***********************************
**   Newer version is available!
**
**         Current: %s
**         Latest: %s
**
**   To get the latest version
**   run: %s upgrade
***********************************`, curV, v, store.Get().BinaryName)
	log.G().Printf("%s%s%s", color, msg, clearColor)
}

func spaceAccordingly(msg string, params ...interface{}) string {
	lines := strings.Split(msg, "\n")
	fullLength := len(lines[0])
	tplIdx := 0

	for idx, line := range lines {
		if strings.Contains(line, "%") {
			line = fmt.Sprintf(line, params[tplIdx])
			tplIdx++
		}

		reqSpaceLeft := fullLength - len(line)
		space := strings.Builder{}
		space.Grow(reqSpaceLeft)
		for i := 0; i < reqSpaceLeft; i++ {
			_, _ = space.WriteString(" ")
		}
		line = fmt.Sprintf("%s%s**", line, space.String())
		lines[idx] = line
	}

	return strings.Join(lines, "\n")
}

func getLatestCliVersion(ctx context.Context) (*semver.Version, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", store.Get().CLILatestVersionFileLink, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request to get latest version: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest version file: %w", err)
	}

	defer res.Body.Close()

	buf := &bytes.Buffer{}

	if _, err := io.Copy(buf, res.Body); err != nil {
		return nil, fmt.Errorf("failed to copy temp version file: %w", err)
	}

	vStr := strings.TrimSpace(buf.String())

	v, err := semver.NewVersion(vStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version '%s': %w", vStr, err)
	}

	return v, nil
}

func hasSkipCheckAnnotation(cmd *cobra.Command) bool {
	if cmd.Annotations == nil {
		return false
	}

	_, ok := cmd.Annotations[SkipVersionCheck]
	return ok
}

func downloadAndExtract(ctx context.Context, url, version string) (string, error) {
	log.G(ctx).Debugf("Downloading cli using download link: %s", url)
	log.G(ctx).Infof("Downloading CLI version: %s...", version)

	// create temp file
	tarfile, err := ioutil.TempFile("", fmt.Sprintf("*.cf-%s.tar.gz", version))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer cleanTempFile(tarfile)

	// download tar file
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed send request: %w", err)
	}
	defer res.Body.Close()

	var bytes int64
	if bytes, err = io.Copy(tarfile, res.Body); err != nil {
		return "", fmt.Errorf("failed to copy temp version file: %w", err)
	}

	// back to the beginning
	_, _ = tarfile.Seek(0, 0)

	log.G(ctx).Debugf("downloaded %v bytes", bytes)
	log.G(ctx).Info("Extracting...")

	binaryFile, err := decompressTarStream(ctx, tarfile, version)
	if err != nil {
		return "", fmt.Errorf("failed decompress cli tar file: %w", err)
	}

	log.G(ctx).Debugf("extracted new binary to: %s", binaryFile)

	if err := os.Chmod(binaryFile, 0755); err != nil {
		return "", fmt.Errorf("failed to change file permissions: %w", err)
	}

	return binaryFile, nil
}

func getCurrentBinaryPath() (string, error) {
	binPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get binary path: %w", err)
	}

	return filepath.EvalSymlinks(binPath)
}

func cleanTempFile(f *os.File) {
	log.G().Debugf("cleaning temp file: %s", f.Name())
	if err := f.Close(); err != nil {
		log.G().Debugf("failed to close temp file: %s", err.Error())
	}

	if err := os.Remove(f.Name()); err != nil {
		log.G().Debugf("failed to remove temp file: %s", err.Error())
	}
}

func decompressTarStream(ctx context.Context, r io.Reader, version string) (string, error) {
	expectedFile := fmt.Sprintf(expectedBinFile, build.Default.GOOS, build.Default.GOARCH)
	uncompressedStream, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("failed to create new gzip reader: %w", err)
	}

	tarReader := tar.NewReader(uncompressedStream)

	td, err := ioutil.TempDir("", fmt.Sprintf("cf-%s-*", version))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	binFileName := ""

	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return "", fmt.Errorf("failed to call tar.Next(): %w", err)
		}

		path := ""
		if header.Name != "" {
			path = filepath.Join(td, header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			log.G(ctx).Debugf("creating directory: %s", path)
			if err := os.Mkdir(path, 0755); err != nil {
				return "", fmt.Errorf("failed to create dir %s: %w", path, err)
			}
		case tar.TypeReg:
			log.G(ctx).Debugf("extracting file: %s", path)
			outFile, err := os.Create(path)
			if err != nil {
				return "", fmt.Errorf("failed to create file: %w", err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return "", fmt.Errorf("failed to write to file %s: %w", path, err)
			}
			outFile.Close()
			log.G(ctx).Debugf("done extracting file: %s", path)
			if header.Name == expectedFile {
				binFileName = path
			}
		default:
			return "", fmt.Errorf("uknown tar type: %v in %v", header.Typeflag, header.Name)
		}
	}

	if binFileName == "" {
		return "", fmt.Errorf("did not find the expected binary inside tar archive")
	}

	return binFileName, nil
}
