## cli-v2 cluster remove

Removes a cluster from a given runtime

```
cli-v2 cluster remove [RUNTIME_NAME] [flags]
```

### Examples

```
cli-v2 cluster remove my-runtime --server-url https://<some-hash>.gr7.us-east-1.eks.amazonaws.com
```

### Options

```
  -h, --help                help for remove
      --server-url string   The cluster's server url
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

