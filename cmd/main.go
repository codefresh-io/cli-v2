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
	"context"
	"syscall"

	"github.com/codefresh-io/cli-v2/cmd/commands"
	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
	apu "github.com/codefresh-io/cli-v2/pkg/util/aputil"

	"github.com/sirupsen/logrus"
)

//go:generate sh -c "echo  generating command docs... && cd .. && go run ./hack/cmd-docs/main.go"

func main() {
	ctx := context.Background()
	lgr := log.FromLogrus(logrus.NewEntry(logrus.New()), &log.LogrusConfig{Level: "info"})
	ctx = log.WithLogger(ctx, lgr)
	ctx = util.ContextWithCancelOnSignals(ctx, syscall.SIGINT, syscall.SIGTERM)

	c := commands.NewRoot()

	lgr.AddPFlags(c)

	// configure autopilot logger
	apu.ConfigureLoggerOrDie(c)

	if err := c.ExecuteContext(ctx); err != nil {
		log.G(ctx).Fatal(err)
	}
}
