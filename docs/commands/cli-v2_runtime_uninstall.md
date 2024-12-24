## cli-v2 runtime uninstall

Uninstall a Codefresh runtime

```
cli-v2 runtime uninstall [RUNTIME_NAME] [flags]
```

### Examples

```

# To run this command you need to create a personal access token for your git provider
# and provide it using:

        export GIT_TOKEN=<token>

# or with the flag:

        --git-token <token>

# Deletes a runtime

    cli-v2 runtime uninstall runtime-name --repo gitops_repo

```

### Options

```
      --disable-telemetry       If true, will disable the analytics reporting for the uninstall process
      --force                   If true, will guarantee the runtime is removed from the platform, even in case of errors while cleaning the repo and the cluster
  -h, --help                    help for uninstall
      --wait-timeout duration   How long to wait for the runtime components to be deleted (default 8m0s)
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

