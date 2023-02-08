## cli-v2 runtime upgrade

Upgrade a Codefresh runtime

```
cli-v2 runtime upgrade [RUNTIME_NAME] [flags]
```

### Examples

```

# To run this command you need to create a personal access token for your git provider
# and provide it using:

        export GIT_TOKEN=<token>

# or with the flag:

        --git-token <token>

# Upgrade a runtime to version v0.0.30

    cli-v2 runtime upgrade runtime-name --version 0.0.30 --repo gitops_repo

```

### Options

```
      --disable-telemetry           If true, will disable analytics reporting for the upgrade process
      --git-server-crt string       Git Server certificate file
  -t, --git-token string            Your git provider api token [GIT_TOKEN]
  -u, --git-user string             Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                        help for upgrade
      --repo string                 Repository URL [GIT_REPO]
      --shared-config-repo string   URL to the shared configurations repo. (default: <installation-repo> or the existing one for this account)
      --skip-ingress                Skips the creation of ingress resources
  -b, --upsert-branch               If true will try to checkout the specified branch and create it if it doesn't exist
      --version string              The runtime version to upgrade to, defaults to stable
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

