package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/spf13/cobra"
)

// we don't want to slow down the cli so it is noticable
// so you get 1.5 seconds to check the version, which should
// be enough for most configurations
var getVersionTimeout = time.Millisecond * 1500

const (
	color      = "\u001b[38;5;220m"
	clearColor = "\033[0m"
)

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

func AddCLIVersionCheck(cmd *cobra.Command) {
	var skipCheck bool

	initFunc := func(cmd *cobra.Command) {
		orgPreRunE := cmd.PreRunE

		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if !skipCheck {
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
*    Newer version is available!
*
*         Current: %s
*         Latest: %s
*
*  To get the latest version
*  run: %s upgrade
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
		line = fmt.Sprintf("%s%s*", line, space.String())
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
