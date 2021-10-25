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
      --git-src-git-token string   Your git provider api token [GIT_SRC_GIT_TOKEN]
      --git-src-git-user string    Your git provider user name [GIT_SRC_GIT_USER] (not required in GitHub)
      --git-src-provider string    The git provider, one of: gitea|github
      --git-src-repo string        Repository URL [GIT_SRC_GIT_REPO]
  -t, --git-token string           Your git provider api token [GIT_TOKEN]
  -u, --git-user string            Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                       help for install
      --ingress-host string        The ingress host
      --kubeconfig string          Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string           If present, the namespace scope for this CLI request
      --provider string            The git provider, one of: gitea|github
      --repo string                Repository URL [GIT_REPO]
      --version string             The runtime version to install, defaults to latest
      --wait-timeout duration      How long to wait for the runtime components to be ready (default 8m0s)
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
      --silent                     Disables the command wizard
```

### SEE ALSO

* [cli-v2 runtime](cli-v2_runtime.md)	 - Manage Codefresh runtimes

