## cli-v2 upgrade

Upgrades the cli

```
cli-v2 upgrade [flags]
```

### Options

```
  -h, --help             help for upgrade
  -o, --ouput string     Where to save the new binary (default: replace the old binary)
      --version string   Specify a cli version to upgrade to
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --insecure-ingress-host      Disable certificate validation of ingress host (default: false)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2](cli-v2.md)	 - cli-v2 is used for installing and managing codefresh installations using gitops

