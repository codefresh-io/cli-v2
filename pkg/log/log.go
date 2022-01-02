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

package log

import (
	"context"

	"github.com/spf13/cobra"
)

var (
	G = GetLogger

	L Logger = NopLogger{}
)

type (
	loggerKey struct{}
	NopLogger struct{}
)

type Fields map[string]interface{}

type Logger interface {
	Printf(string, ...interface{})
	Debug(...interface{})
	Info(...interface{})
	Warn(...interface{})
	Fatal(...interface{})
	Error(...interface{})
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Fatalf(string, ...interface{})
	Errorf(string, ...interface{})

	WithField(string, interface{}) Logger
	WithFields(Fields) Logger
	WithError(error) Logger

	// AddPFlags adds persistent logger flags to cmd
	AddPFlags(*cobra.Command)
}

func WithLogger(ctx context.Context, logger Logger) context.Context {
	if L != nil {
		L = logger
	}

	return context.WithValue(ctx, loggerKey{}, logger)
}

func SetDefault(logger Logger) {
	L = logger
}

func GetLogger(ctx ...context.Context) Logger {
	if len(ctx) == 0 {
		if L == nil {
			panic("default logger not initialized")
		}

		return L
	}

	logger := ctx[0].Value(loggerKey{})
	if logger == nil {
		if L == nil {
			panic("default logger not initialized")
		}

		return L
	}

	return logger.(Logger)
}

func (NopLogger) AddPFlags(*cobra.Command)               {}
func (NopLogger) Printf(string, ...interface{})          {}
func (NopLogger) Debug(...interface{})                   {}
func (NopLogger) Info(...interface{})                    {}
func (NopLogger) Warn(...interface{})                    {}
func (NopLogger) Fatal(...interface{})                   {}
func (NopLogger) Error(...interface{})                   {}
func (NopLogger) Debugf(string, ...interface{})          {}
func (NopLogger) Infof(string, ...interface{})           {}
func (NopLogger) Warnf(string, ...interface{})           {}
func (NopLogger) Fatalf(string, ...interface{})          {}
func (NopLogger) Errorf(string, ...interface{})          {}
func (l NopLogger) WithField(string, interface{}) Logger { return l }
func (l NopLogger) WithFields(Fields) Logger             { return l }
func (l NopLogger) WithError(error) Logger               { return l }
