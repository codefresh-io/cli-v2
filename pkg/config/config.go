package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/codefresh-io/cli-v2/pkg/log"
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

type Config struct {
	insecure       bool
	path           string
	requestTimeout time.Duration
	CurrentContext string                 `json:"current-context"`
	Contexts       map[string]AuthContext `json:"contexts"`
}

type AuthContext struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Beta   bool   `json:"beta"`
	OnPrem bool   `json:"onPrem"`
}

func AddFlags(f *pflag.FlagSet) *Config {
	conf := &Config{path: defaultPath}

	f.StringVar(&conf.path, "cfconfig", defaultPath, "Custom path for authentication contexts config file")
	f.BoolVar(&conf.insecure, "insecure", false, "Disable certificate validation for TLS connections (e.g. to g.codefresh.io)")
	f.DurationVar(&conf.requestTimeout, "request-timeout", defaultRequestTimeout, "Request timeout")

	return conf
}

func (c *Config) Load(pathOverride string) error {
	viper.SetConfigType(configFileFormat)
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(c.path)

	if err := viper.ReadInConfig(); err != nil {
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

	return codefresh.New(&codefresh.ClientOptions{
		Auth: codefresh.AuthOptions{
			Token: ctx.Token,
		},
		Host:   ctx.URL,
		Client: httpClient,
	})
}

func (c *Config) Write(ctx context.Context, w io.Writer) error {
	tb := tabwriter.NewWriter(w, 0, 0, 4, ' ', 0)
	_, err := tb.Write([]byte("NAME\tURL\tACCOUNT\tSTATUS"))
	if err != nil {
		return err
	}

	for name, context := range c.Contexts {
		status := "VALID"
		usr, err := c.clientForContext(context).Users().GetCurrent(ctx)
		if err != nil {
			status = "REVOKED"
		}
		acc := usr.GetActiveAccount()
		_, err = tb.Write([]byte(fmt.Sprintf("%s\t%s\t%s\t%s",
			name,
			context.URL,
			acc.Name,
			status,
		)))
		if err != nil {
			return err
		}
	}

	return nil
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
	defaultPath = filepath.Join(homedir, configFileName)
}
