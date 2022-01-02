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

package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/ghodss/yaml"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
)

const configFileName = ".cfconfig"
const configFileFormat = "yaml"
const defaultRequestTimeout = time.Second * 30

var greenStar = color.GreenString("*")
var defaultPath = ""

// Errors
var (
	ErrInvalidConfig = errors.New("invalid config")

	ErrContextDoesNotExist = func(context string) error {
		return fmt.Errorf(
			util.Doc(
				fmt.Sprintf("%s: current context '%s' does not exist in config file. run '<BIN> config create-context' to create one.", ErrInvalidConfig, context),
			),
		)
	}
)

var newCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return codefresh.New(opts) }

type Config struct {
	insecure        bool
	path            string
	contextOverride string
	requestTimeout  time.Duration
	CurrentContext  string                  `mapstructure:"current-context" json:"current-context"`
	Contexts        map[string]*AuthContext `mapstructure:"contexts" json:"contexts"`
}

type AuthContext struct {
	Type           string `mapstructure:"type" json:"type"`
	Name           string `mapstructure:"name" json:"name"`
	URL            string `mapstructure:"url" json:"url"`
	Token          string `mapstructure:"token" json:"token"`
	Beta           bool   `mapstructure:"beta" json:"beta"`
	OnPrem         bool   `mapstructure:"onPrem" json:"onPrem"`
	DefaultRuntime string `mapstructure:"defaultRuntime" json:"defaultRuntime"`
}

func (ac *AuthContext) IsProduction() bool {
	return ac.URL == store.Get().DefaultAPI
}

func AddFlags(f *pflag.FlagSet) *Config {
	conf := &Config{path: defaultPath}

	f.StringVar(&conf.path, "cfconfig", defaultPath, "Custom path for authentication contexts config file")
	f.StringVar(&conf.contextOverride, "auth-context", "", "Run the next command using a specific authentication context")
	f.BoolVar(&conf.insecure, "insecure", false, "Disable certificate validation for TLS connections (e.g. to g.codefresh.io)")
	f.DurationVar(&conf.requestTimeout, "request-timeout", defaultRequestTimeout, "Request timeout")

	return conf
}

// RequireAuthentication is ment to be used as cobra PreRunE or PersistentPreRunE function
// on commands that require authentication context.
func (c *Config) RequireAuthentication(cmd *cobra.Command, args []string) error {
	if err := c.Load(cmd, args); err != nil {
		return err
	}

	if len(c.Contexts) == 0 {
		return fmt.Errorf(util.Doc("%s: command requires authentication, run '<BIN> config create-context'"), cmd.CommandPath())
	}

	c.validate()

	return nil
}

func (c *Config) Load(cmd *cobra.Command, args []string) error {
	viper.SetConfigType(configFileFormat)
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(c.path)

	if err := viper.ReadInConfig(); err != nil {
		if errors.As(err, &viper.ConfigFileNotFoundError{}) {
			log.G().Debug("config file not found")
			if c.path == defaultPath {
				return nil
			}
		}
		return err
	}

	if err := viper.Unmarshal(c); err != nil {
		return err
	}

	c.validate()

	return nil
}

// Save persists the config to the file it was read from
func (c *Config) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(c.path, configFileName), data, 0644)
}

// GetCurrentContext returns current authentication context
// or the one specified with --auth-context.
func (c *Config) GetCurrentContext() *AuthContext {
	ctx := c.CurrentContext
	if c.contextOverride != "" {
		ctx = c.contextOverride
	}
	return c.Contexts[ctx]
}

// NewClient creates a new codefresh client for the current context or for
// override context (if specified with --auth-context).
func (c *Config) NewClient() codefresh.Codefresh {
	return c.clientForContext(c.GetCurrentContext())
}

// Delete
func (c *Config) DeleteContext(name string) error {
	if _, exists := c.Contexts[name]; !exists {
		return ErrContextDoesNotExist(name)
	}

	delete(c.Contexts, name)
	if c.CurrentContext == name {
		log.G().Warnf(util.Doc("delete context is set as current context, specify a new current context with '<BIN> config use-context'"))
		c.CurrentContext = ""
	}

	return c.Save()
}

func (c *Config) UseContext(ctx context.Context, name string) error {
	if _, exists := c.Contexts[name]; !exists {
		return ErrContextDoesNotExist(name)
	}

	c.CurrentContext = name
	_, err := c.NewClient().Users().GetCurrent(ctx)
	if err != nil {
		return err
	}

	return c.Save()
}

func (c *Config) CreateContext(ctx context.Context, name, token, url string) error {
	if _, exists := c.Contexts[name]; exists {
		return fmt.Errorf("authentication context with the name '%s' already exists", name)
	}

	authCtx := &AuthContext{
		Name:  name,
		URL:   url,
		Token: token,
		Type:  "APIKey",
		Beta:  false,
	}

	// validate new context
	client := c.clientForContext(authCtx)
	usr, err := client.Users().GetCurrent(ctx)
	if err != nil {
		return fmt.Errorf("failed to create '%s' with the provided options: %w", name, err)
	}
	authCtx.OnPrem = isAdminUser(usr)

	if c.Contexts == nil {
		c.Contexts = map[string]*AuthContext{}
	}
	c.Contexts[name] = authCtx
	return nil
}

func (c *Config) clientForContext(ctx *AuthContext) codefresh.Codefresh {
	httpClient := &http.Client{}
	httpClient.Timeout = c.requestTimeout
	if c.insecure {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = customTransport
	}

	return newCodefresh(&codefresh.ClientOptions{
		Host:   ctx.URL,
		Auth: codefresh.AuthOptions{
			Token: ctx.Token,
		},
		Client: httpClient,
	})
}

func (c *Config) Write(ctx context.Context, w io.Writer) error {
	tb := ansiterm.NewTabWriter(w, 0, 0, 4, ' ', 0)
	writerLock := sync.Mutex{}
	ar := util.NewAsyncRunner(len(c.Contexts))

	_, err := fmt.Fprintln(tb, "CURRENT\tNAME\tURL\tACCOUNT\tSTATUS")
	if err != nil {
		return err
	}

	for name, context := range c.Contexts {
		// capture local variables for closure
		name := name
		context := context

		ar.Run(func() error {
			status := "VALID"
			accName := ""
			current := ""

			usr, err := c.clientForContext(context).Users().GetCurrent(ctx)
			if err != nil {
				if ctx.Err() != nil { // context canceled
					return ctx.Err()
				}
				status = err.Error()

			} else {
				accName = usr.GetActiveAccount().Name
			}

			if name == c.CurrentContext {
				current = greenStar
			}

			writerLock.Lock()
			_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\n",
				current,
				name,
				context.URL,
				accName,
				status,
			)
			writerLock.Unlock()
			if err != nil {
				return err
			}
			return nil
		})
	}

	if err := ar.Wait(); err != nil {
		return err
	}

	return tb.Flush()
}

func (c *Config) validate() {
	if c.contextOverride != "" {
		if _, ok := c.Contexts[c.contextOverride]; !ok {
			log.G().Fatalf("%s: selected context '%s' does not exist in config file", ErrInvalidConfig, c.contextOverride)
		}
	}

	if _, ok := c.Contexts[c.CurrentContext]; !ok && c.CurrentContext != "" {
		log.G().Fatalf("%s: current context '%s' does not exist in config file", ErrInvalidConfig, c.CurrentContext)
	}
}

func isAdminUser(usr *codefresh.User) bool {
	for _, role := range usr.Roles {
		if role == "Admin" {
			return true
		}
	}
	return false
}

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.G().WithError(err).Fatal("failed to get user home directory")
	}
	defaultPath = homedir
}
