## cli-v2 runtime logs

Work with current runtime logs

```
cli-v2 runtime logs [--ingress-host <url>] [--download] [flags]
```

### Options

```
      --download              If true, will download logs from all componnents that consist of current runtime
  -h, --help                  help for logs
      --ingress-host string   Set runtime ingress host
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --insecure-ingress-host      Disable certificate validation of ingress host (default: false)
      --request-timeout duration   Request timeout (default 30s)
      --silent                     Disables the command wizard
```

### SEE ALSO

* [cli-v2 runtime](cli-v2_runtime.md)	 - Manage Codefresh runtimes

