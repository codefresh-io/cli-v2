## cli-v2 runtime

Manage Codefresh runtimes

```
cli-v2 runtime [flags]
```

### Options

```
  -h, --help     help for runtime
      --silent   Disables the command wizard
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
* [cli-v2 runtime install](cli-v2_runtime_install.md)	 - Install a new Codefresh runtime
* [cli-v2 runtime list](cli-v2_runtime_list.md)	 - List all Codefresh runtimes
* [cli-v2 runtime uninstall](cli-v2_runtime_uninstall.md)	 - Uninstall a Codefresh runtime
* [cli-v2 runtime upgrade](cli-v2_runtime_upgrade.md)	 - Upgrade a Codefresh runtime

