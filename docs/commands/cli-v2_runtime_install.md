## cli-v2 runtime install

Install a new Codefresh runtime

```
cli-v2 runtime install [runtime_name] [flags]
```

### Examples

```

# To run this command you need to create a personal access token for your git provider
# and provide it using:

        export GIT_TOKEN=<token>

# or with the flag:

        --git-token <token>

# Adds a new runtime

    cli-v2 runtime install runtime-name --repo gitops_repo

```

### Options

```
      --context string              The name of the kubeconfig context to use
      --demo-resources              Installs demo resources (default: true) (default true)
      --disable-rollback            If true, will not perform installation rollback after a failed installation
      --disable-telemetry           If true, will disable the analytics reporting for the installation process
  -t, --git-token string            Your git provider api token [GIT_TOKEN]
  -u, --git-user string             Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                        help for install
      --ingress-class string        The ingress class name
      --ingress-host string         The ingress host
      --kubeconfig string           Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string            If present, the namespace scope for this CLI request
      --personal-git-token string   The Personal git token for your user
      --provider string             The git provider, one of: azure|gitea|github|gitlab
      --provider-api-url string     Git provider API url
      --repo string                 Repository URL [GIT_REPO]
      --skip-cluster-checks         Skips the cluster's checks
      --skip-ingress                Skips the creation of ingress resources
  -b, --upsert-branch               If true will try to checkout the specified branch and create it if it doesn't exist
      --version string              The runtime version to install (default: latest)
      --wait-timeout duration       How long to wait for the runtime components to be ready (default 8m0s)
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

