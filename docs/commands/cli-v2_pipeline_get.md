## cli-v2 pipeline get

Get a pipeline under a specific runtime and namespace

```
cli-v2 pipeline get --runtime <runtime> --namespace <namespace> --name <name> [flags]
```

### Examples

```

            cli-v2 pipeline --runtime runtime_name --namespace namespace --name pipeline_name

            cli-v2 pipeline -r runtime_name -N namespace -n pipeline_name
        
```

### Options

```
  -h, --help               help for get
  -n, --name string        Name of target pipeline
  -N, --namespace string   Namespace of target pipeline
  -r, --runtime string     Runtime name of target pipeline
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2 pipeline](cli-v2_pipeline.md)	 - Manage pipelines of Codefresh runtimes

