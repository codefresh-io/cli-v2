## cli-v2 cluster add

Add a cluster to a given runtime

```
cli-v2 cluster add [RUNTIME_NAME] [flags]
```

### Examples

```
cli-v2 cluster add my-runtime --context my-context
```

### Options

```
      --annotations stringToString   Set metadata annotations (e.g. --annotation key=value) (default [])
      --context string               The name of the kubeconfig context to use
      --dry-run
  -h, --help                         help for add
      --kubeconfig string            Path to the kubeconfig file to use for CLI requests.
      --labels stringToString        Set metadata labels (e.g. --label key=value) (default [])
      --name string                  Name of the cluster. If omitted, will use the context name
  -n, --namespace string             If present, the namespace scope for this CLI request
      --skip-tls-validation          Set true to skip TLS validation of domain for cluster server URL                      
      --system-namespace string      Use different system namespace (default "kube-system") (default "kube-system")
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

