## cli-v2 git-source list

List all Codefresh git-sources of a given runtime

```
cli-v2 git-source list RUNTIME_NAME [flags]
```

### Examples

```
cli-v2 git-source list my-runtime
```

### Options

```
  -h, --help               help for list
      --include-internal   If true, will include the Codefresh internal git-sources
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

* [cli-v2 git-source](cli-v2_git-source.md)	 - Manage git-sources of Codefresh runtimes

