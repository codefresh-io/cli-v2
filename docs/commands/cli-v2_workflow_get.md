## cli-v2 workflow get

Get a workflow under a specific uid

```
cli-v2 workflow get [uid] [flags]
```

### Examples

```

            cli-v2 workflow get 0732b138-b74c-4a5e-b065-e23e6da0803d
        
```

### Options

```
  -h, --help   help for get
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

* [cli-v2 workflow](cli-v2_workflow.md)	 - Manage workflows of Codefresh runtimes

