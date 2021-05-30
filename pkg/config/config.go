package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/juju/ansiterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/codefresh-io/cli-v2/pkg/log"
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
)

var newCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return codefresh.New(opts) }

type Config struct {
	insecure        bool
	path            string
	contextOverride string
	requestTimeout  time.Duration
	CurrentContext  string                 `mapstructure:"current-context"`
	Contexts        map[string]AuthContext `mapstructure:"contexts"`
}

type AuthContext struct {
	Type   string `mapstructure:"type"`
	Name   string `mapstructure:"name"`
	URL    string `mapstructure:"url"`
	Token  string `mapstructure:"token"`
	Beta   bool   `mapstructure:"beta"`
	OnPrem bool   `mapstructure:"onPrem"`
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
	if len(c.Contexts) == 0 {
		return fmt.Errorf(util.Doc("%s: command requires authentication, run '<BIN> auth create-context'"), cmd.CommandPath())
	}
	return nil
}

func (c *Config) Load() error {
	viper.SetConfigType(configFileFormat)
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(c.path)

	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, &viper.ConfigFileNotFoundError{}) {
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

// GetCurrentContext returns current authentication context
// or the one specified with --auth-context.
func (c *Config) GetCurrentContext() AuthContext {
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

func (c *Config) clientForContext(ctx AuthContext) codefresh.Codefresh {
	httpClient := &http.Client{}
	httpClient.Timeout = c.requestTimeout
	if c.insecure {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = customTransport
	}

	return newCodefresh(&codefresh.ClientOptions{
		Auth: codefresh.AuthOptions{
			Token: ctx.Token,
		},
		Host:   ctx.URL,
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

	if _, ok := c.Contexts[c.CurrentContext]; !ok {
		log.G().Fatalf("%s: current context '%s' does not exist in config file", ErrInvalidConfig, c.CurrentContext)
	}
}

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.G().WithError(err).Fatal("failed to get user home directory")
	}
	defaultPath = homedir
}
