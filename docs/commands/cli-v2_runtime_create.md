## cli-v2 runtime create

Create a new Codefresh runtime

```
cli-v2 runtime create [runtime_name] [flags]
```

### Examples

```

# To run this command you need to create a personal access token for your git provider
# and provide it using:

        export INSTALL_GIT_TOKEN=<token>

# or with the flag:

        --install-git-token <token>

# Adds a new runtime

    cli-v2 runtime create runtime-name --install-owner owner --install-name gitops_repo

```

### Options

```
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cache-dir string               Default cache directory (default "/home/user/.kube/cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
  -h, --help                           help for create
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --install-git-token string       Your git provider api token [INSTALL_GIT_TOKEN]
      --install-host string            The git provider address (for on-premise git providers)
      --install-name string            The name of the repository
      --install-owner string           The name of the owner or organiaion
      --install-provider string        The git provider, one of: github (default "github")
      --install-public                 If true, will create the repository as public (default is false)
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string               If present, the namespace scope for this CLI request
  -s, --server string                  The address and port of the Kubernetes API server
      --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
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

