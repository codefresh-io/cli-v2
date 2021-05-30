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
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/codefresh-io/cli-v2/pkg/log"
	"github.com/codefresh-io/cli-v2/pkg/util"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
)

const configFileName = ".cfconfig"
const configFileFormat = "yaml"
const defaultRequestTimeout = time.Second * 30

var defaultPath = ""
var stdout = os.Stdout

// Errors
var (
	ErrInvalidConfig = errors.New("invalid config")
)

var newCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return codefresh.New(opts) }

type Config struct {
	insecure       bool
	path           string
	requestTimeout time.Duration
	CurrentContext string                 `mapstructure:"current-context"`
	Contexts       map[string]AuthContext `mapstructure:"contexts"`
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
	f.BoolVar(&conf.insecure, "insecure", false, "Disable certificate validation for TLS connections (e.g. to g.codefresh.io)")
	f.DurationVar(&conf.requestTimeout, "request-timeout", defaultRequestTimeout, "Request timeout")

	return conf
}

func (c *Config) Load() error {
	viper.SetConfigType(configFileFormat)
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(c.path)

	if err := viper.ReadInConfig(); err != nil {
		if errors.As(err, &viper.ConfigFileNotFoundError{}) {
			log.G().Debug("config file not found")
		}
		return err
	}

	if err := viper.Unmarshal(c); err != nil {
		return err
	}

	c.validate()

	return nil
}

func (c *Config) GetCurrentContext() AuthContext {
	return c.Contexts[c.CurrentContext]
}

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
	tb := tabwriter.NewWriter(w, 0, 0, 8, ' ', 0)
	writerLock := sync.Mutex{}
	ar := util.NewAsyncRunner(len(c.Contexts))

	_, err := fmt.Fprintln(tb, "NAME\tURL\tACCOUNT\tSTATUS")
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

			usr, err := c.clientForContext(context).Users().GetCurrent(ctx)
			if err != nil {
				if ctx.Err() != nil { // context canceled
					return ctx.Err()
				}
				status = err.Error()

			} else {
				accName = usr.GetActiveAccount().Name
			}

			writerLock.Lock()
			_, err = fmt.Fprintf(tb, "%s\t%s\t%s\t%s\n",
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
	if _, ok := c.Contexts[c.CurrentContext]; !ok {
		log.G().WithError(ErrInvalidConfig).Fatalf("current context '%s' does not exist in config file", c.CurrentContext)
	}
}

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.G().WithError(err).Fatal("failed to get user home directory")
	}
	defaultPath = homedir
}
