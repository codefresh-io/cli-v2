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

package log

import (
	"fmt"

	cmdutil "github.com/argoproj/argo-cd/v2/cmd/util"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	defaultLvl       = logrus.InfoLevel
	defaultFormatter = "text"
)

type LogrusFormatter string

type LogrusConfig struct {
	Level  string
	Format LogrusFormatter
}

type logrusAdapter struct {
	*logrus.Entry
	c *LogrusConfig
}

const (
	FormatterText LogrusFormatter = defaultFormatter
	FormatterJSON LogrusFormatter = "json"
)

func FromLogrus(l *logrus.Entry, c *LogrusConfig) Logger {
	if c == nil {
		c = &LogrusConfig{}
	}

	return &logrusAdapter{l, c}
}

func GetLogrusEntry(l Logger) (*logrus.Entry, error) {
	adpt, ok := l.(*logrusAdapter)
	if !ok {
		return nil, fmt.Errorf("not a logrus logger")
	}

	return adpt.Entry, nil
}

func initCommands(cmds []*cobra.Command, initFunc func(*cobra.Command)) {
	for _, cmd := range cmds {
		initFunc(cmd)
		if cmd.HasSubCommands() {
			initCommands(cmd.Commands(), initFunc)
		}
	}
}

func (l *logrusAdapter) AddPFlags(cmd *cobra.Command) {
	flags := pflag.NewFlagSet("logrus", pflag.ContinueOnError)
	flags.StringVar(&l.c.Level, "log-level", l.c.Level, `set the log level, e.g. "debug", "info", "warn", "error"`)
	format := flags.String("log-format", defaultFormatter, `set the log format: "text", "json"`)

	cmd.PersistentFlags().AddFlagSet(flags)

	initFunc := func(cmd *cobra.Command) {
		orgPreRunE := cmd.PreRunE

		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			switch *format {
			case string(FormatterJSON), string(FormatterText):
				l.c.Format = LogrusFormatter(*format)
			default:
				return fmt.Errorf("invalid log format: %s", *format)
			}

			if err := l.configure(flags); err != nil {
				return err
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

	cobra.OnInitialize(func() { initCommands(cmd.Commands(), initFunc) })

	cmdutil.LogFormat = *format
	cmdutil.LogLevel = l.c.Level
}

func (l *logrusAdapter) Printf(format string, args ...interface{}) {
	if len(args) > 0 {
		fmt.Printf(fmt.Sprintf("%s\n", format), args...)
	} else {
		fmt.Println(format)
	}
}

func (l *logrusAdapter) WithField(key string, val interface{}) Logger {
	return FromLogrus(l.Entry.WithField(key, val), l.c)
}

func (l *logrusAdapter) WithFields(fields Fields) Logger {
	return FromLogrus(l.Entry.WithFields(logrus.Fields(fields)), l.c)
}

func (l *logrusAdapter) WithError(err error) Logger {
	return FromLogrus(l.Entry.WithError(err), l.c)
}

func (l *logrusAdapter) configure(f *pflag.FlagSet) error {
	var (
		err  error
		fmtr logrus.Formatter
		lvl  = defaultLvl
	)

	if l.c.Level != "" {
		lvl, err = logrus.ParseLevel(l.c.Level)
		if err != nil {
			return err
		}
	}

	if lvl < logrus.DebugLevel {
		fmtr = &logrus.TextFormatter{
			DisableTimestamp:       true,
			DisableLevelTruncation: true,
		}
	} else {
		fmtr = &logrus.TextFormatter{
			FullTimestamp: true,
		}
	}

	if l.c.Format == FormatterJSON {
		fmtr = &logrus.JSONFormatter{}
	}

	l.Logger.SetLevel(lvl)
	l.Logger.SetFormatter(fmtr)

	return nil
}
