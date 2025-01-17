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

package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/store"
	"github.com/codefresh-io/cli-v2/pkg/util"

	apgit "github.com/argoproj-labs/argocd-autopilot/pkg/git"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	cfrest "github.com/codefresh-io/go-sdk/pkg/rest"
	"github.com/fatih/color"
	"github.com/ghodss/yaml"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate mockgen -destination=./mocks/config.go -package=config -source=./config.go Config

const (
	configFileName        = ".cfconfig"
	configFileFormat      = "yaml"
	defaultRequestTimeout = time.Second * 30
)

type (
	Config interface {
		CreateContext(ctx context.Context, name, token, url, caCert string) error
		DeleteContext(name string) error
		GetAccountId(ctx context.Context) (string, error)
		GetCurrentContext() *AuthContext
		GetUser(ctx context.Context) (*cfrest.User, error)
		Load(cmd *cobra.Command, args []string) error
		NewAdHocClient(ctx context.Context, url, token, caCert string) (codefresh.Codefresh, error)
		NewClient() codefresh.Codefresh
		RequireAuthentication(cmd *cobra.Command, args []string) error
		Save() error
		UseContext(ctx context.Context, name string) error
		Write(ctx context.Context, w io.Writer) error
	}

	ConfigImpl struct {
		insecure        bool
		path            string
		contextOverride string
		requestTimeout  time.Duration
		CurrentContext  string                  `mapstructure:"current-context" json:"current-context"`
		Contexts        map[string]*AuthContext `mapstructure:"contexts" json:"contexts"`
	}

	AuthContext struct {
		Type           string `mapstructure:"type" json:"type"`
		Name           string `mapstructure:"name" json:"name"`
		URL            string `mapstructure:"url" json:"url"`
		Token          string `mapstructure:"token" json:"token"`
		DefaultRuntime string `mapstructure:"defaultRuntime" json:"defaultRuntime,omitempty"`
		CACert         string `mapstructure:"caCert" json:"caCert,omitempty"`
	}

	authContextStatus struct {
		current bool
		status  string
		account string
		user    string
	}
)

// Errors
var (
	greenStar        = color.GreenString("*")
	defaultPath      = ""
	ErrInvalidConfig = errors.New("invalid config")

	ErrContextDoesNotExist = func(context string) error {
		return errors.New(
			util.Doc(
				fmt.Sprintf("%s: current context \"%s\" does not exist in config file. run '<BIN> config create-context' to create one.", ErrInvalidConfig, context),
			),
		)
	}

	NewCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return codefresh.New(opts) }
)

func AddFlags(f *pflag.FlagSet) Config {
	conf := &ConfigImpl{path: defaultPath}

	f.StringVar(&conf.path, "cfconfig", defaultPath, "Custom path for authentication contexts config file")
	f.StringVar(&conf.contextOverride, "auth-context", "", "Run the next command using a specific authentication context")
	f.BoolVar(&conf.insecure, "insecure", false, "Disable certificate validation for TLS connections (e.g. to g.codefresh.io)")
	f.BoolVar(&store.Get().InsecureIngressHost, "insecure-ingress-host", false, "Disable certificate validation of ingress host (default: false)")
	f.DurationVar(&conf.requestTimeout, "request-timeout", defaultRequestTimeout, "Request timeout")
	return conf
}

// RequireAuthentication is ment to be used as cobra PreRunE or PersistentPreRunE function
// on commands that require authentication context.
func (c *ConfigImpl) RequireAuthentication(cmd *cobra.Command, args []string) error {
	if err := c.Load(cmd, args); err != nil {
		return err
	}

	if len(c.Contexts) == 0 {
		return fmt.Errorf(util.Doc("%s: command requires authentication, run '<BIN> config create-context'"), cmd.CommandPath())
	}

	return nil
}

func (c *ConfigImpl) Load(_ *cobra.Command, _ []string) error {
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
func (c *ConfigImpl) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(c.path, configFileName), data, 0644)
}

// GetCurrentContext returns current authentication context
// or the one specified with --auth-context.
func (c *ConfigImpl) GetCurrentContext() *AuthContext {
	ctx := c.CurrentContext
	if c.contextOverride != "" {
		ctx = c.contextOverride
	}

	authCtx, ok := c.Contexts[ctx]
	if !ok {
		log.G().Fatalf(util.Doc("Current Codefresh context \"%s\" does not exist. "+
			"You must select another context using '<BIN> config use-context <context>'"), ctx)
	}
	return authCtx
}

// NewClient creates a new codefresh client for the current context or for
// override context (if specified with --auth-context).
func (c *ConfigImpl) NewClient() codefresh.Codefresh {
	client, err := c.clientForContext(c.GetCurrentContext())
	if err != nil {
		panic(err)
	}

	return client
}

func (c *ConfigImpl) NewAdHocClient(ctx context.Context, url, token, caCert string) (codefresh.Codefresh, error) {
	if url == "" {
		url = store.Get().DefaultAPI
	}

	authCtx := &AuthContext{
		Type:   "APIKey",
		Name:   "ad-hoc",
		URL:    url,
		Token:  token,
		CACert: caCert,
	}

	return c.clientForContext(authCtx)
}

// Delete
func (c *ConfigImpl) DeleteContext(name string) error {
	if _, exists := c.Contexts[name]; !exists {
		return ErrContextDoesNotExist(name)
	}

	delete(c.Contexts, name)
	if c.CurrentContext == name {
		log.G().Warnf(util.Doc("Deleted context is set as current context, specify a new current context with '<BIN> config use-context'"))
		c.CurrentContext = ""
	}

	return c.Save()
}

func (c *ConfigImpl) UseContext(ctx context.Context, name string) error {
	if _, exists := c.Contexts[name]; !exists {
		return ErrContextDoesNotExist(name)
	}

	c.CurrentContext = name
	_, err := c.GetUser(ctx)
	if err != nil {
		return err
	}

	return c.Save()
}

func (c *ConfigImpl) CreateContext(ctx context.Context, name, token, url, caCert string) error {
	if _, exists := c.Contexts[name]; exists {
		return fmt.Errorf("authentication context with the name \"%s\" already exists", name)
	}

	authCtx := &AuthContext{
		Type:   "APIKey",
		Name:   name,
		URL:    url,
		Token:  token,
		CACert: caCert,
	}

	// validate new context
	client, err := c.clientForContext(authCtx)
	if err != nil {
		return fmt.Errorf("failed to create \"%s\" with the provided options: %w", name, err)
	}

	_, err = client.Rest().User().GetCurrent(ctx)
	if err != nil {
		return fmt.Errorf("failed to create \"%s\" with the provided options: %w", name, err)
	}

	if c.Contexts == nil {
		c.Contexts = map[string]*AuthContext{}
	}

	c.Contexts[name] = authCtx
	return nil
}

func (c *ConfigImpl) clientForContext(ctx *AuthContext) (codefresh.Codefresh, error) {
	transport, err := apgit.DefaultTransportWithCa(ctx.CACert)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   c.requestTimeout,
	}
	if c.insecure {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	return NewCodefresh(&codefresh.ClientOptions{
		Host:   ctx.URL,
		Token:  ctx.Token,
		Client: httpClient,
	}), nil
}

func (c *ConfigImpl) Write(ctx context.Context, w io.Writer) error {
	tb := ansiterm.NewTabWriter(w, 0, 0, 4, ' ', 0)
	ar := util.NewAsyncRunner(len(c.Contexts))

	_, err := fmt.Fprintln(tb, "CURRENT\tNAME\tURL\tACCOUNT\tUSER\tSTATUS")
	if err != nil {
		return err
	}

	contexts := make([]*AuthContext, 0, len(c.Contexts))
	statuses := make([]*authContextStatus, 0, len(c.Contexts))
	for _, context := range c.Contexts {
		contexts = append(contexts, context)
		statuses = append(statuses, &authContextStatus{})
	}

	sort.SliceStable(contexts, func(i, j int) bool {
		return contexts[i].Name < contexts[j].Name
	})

	for i, authCtx := range contexts {
		// capture local variables for closure
		authCtx := authCtx
		status := statuses[i]

		ar.Run(func() error {
			status.status = "VALID"
			if authCtx.Name == c.CurrentContext {
				status.current = true
			}

			client, err := c.clientForContext(authCtx)
			if err != nil {
				if ctx.Err() != nil { // context canceled
					return ctx.Err()
				}

				status.status = err.Error()
				return nil
			}

			usr, err := client.Rest().User().GetCurrent(ctx)
			if err != nil {
				if ctx.Err() != nil { // context canceled
					return ctx.Err()
				}

				status.status = err.Error()
			} else {
				status.account = usr.GetActiveAccount().Name
				status.user = usr.Name
			}

			return nil
		})
	}

	if err := ar.Wait(); err != nil {
		return err
	}

	for i, context := range contexts {
		status := statuses[i]
		current := ""
		if status.current {
			current = greenStar
		}

		_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\t%s\t%s\n",
			current,
			context.Name,
			context.URL,
			status.account,
			status.user,
			status.status,
		)
		if err != nil {
			return err
		}
	}

	return tb.Flush()
}

func (c *ConfigImpl) GetUser(ctx context.Context) (*cfrest.User, error) {
	return c.NewClient().Rest().User().GetCurrent(ctx)
}

func (c *ConfigImpl) GetAccountId(ctx context.Context) (string, error) {
	user, err := c.GetUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed getting account id: %w", err)
	}

	return user.GetActiveAccount().ID, nil
}

func (c *ConfigImpl) validate() {
	if c.contextOverride != "" {
		if _, ok := c.Contexts[c.contextOverride]; !ok {
			log.G().Fatalf("%s: selected context \"%s\" does not exist in config file", ErrInvalidConfig, c.contextOverride)
		}
	}

	if _, ok := c.Contexts[c.CurrentContext]; !ok && c.CurrentContext != "" {
		log.G().Fatalf("%s: current context \"%s\" does not exist in config file", ErrInvalidConfig, c.CurrentContext)
	}
}

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.G().WithError(err).Fatal("failed to get user home directory")
	}

	defaultPath = homedir
}
