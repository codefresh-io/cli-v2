## cli-v2 runtime install

Install a new Codefresh runtime

```
cli-v2 runtime install [runtime_name] [flags]
```

### Examples

```

# To run this command you need to create a personal access token for your git provider
# and provide it using:

        export INSTALL_GIT_TOKEN=<token>

# or with the flag:

        --install-git-token <token>

# Adds a new runtime

    cli-v2 runtime install runtime-name --install-repo gitops_repo

```

### Options

```
      --git-src-git-token string   Your git provider api token [GIT_SRC_GIT_TOKEN]
      --git-src-provider string    The git provider, one of: gitea|github
      --git-src-repo string        Repository URL [GIT_SRC_GIT_REPO]
  -h, --help                       help for install
      --install-git-token string   Your git provider api token [INSTALL_GIT_TOKEN]
      --install-provider string    The git provider, one of: github|gitea
      --install-repo string        Repository URL [INSTALL_GIT_REPO]
      --kubeconfig string          Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string           If present, the namespace scope for this CLI request
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2 runtime](cli-v2_runtime.md)	 - Manage Codefresh runtimes

