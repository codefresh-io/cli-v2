## cli-v2 pipeline list

List all the pipelines

```
cli-v2 pipeline list [flags]
```

### Examples

```

            cli-v2 pipelines list

            cli-v2 pipelines list --runtime <runtime>

            cli-v2 pipelines list -r <runtime>
        
```

### Options

```
  -h, --help               help for list
  -n, --name string        Filter by pipeline name
  -N, --namespace string   Filter by pipeline namespace
  -p, --project string     Filter by pipeline project
  -r, --runtime string     Filter by pipeline runtime
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

* [cli-v2 pipeline](cli-v2_pipeline.md)	 - Manage pipelines of Codefresh runtimes

