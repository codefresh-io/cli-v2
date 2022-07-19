## cli-v2 cluster list

List all the clusters of a given runtime

```
cli-v2 cluster list [RUNTIME_NAME] [flags]
```

### Examples

```
cli-v2 cluster list my-runtime
```

### Options

```
  -h, --help   help for list
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

* [cli-v2 cluster](cli-v2_cluster.md)	 - Manage clusters of Codefresh runtimes

