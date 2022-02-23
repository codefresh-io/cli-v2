## cli-v2 component list

List all the components under a specific runtime

```
cli-v2 component list RUNTIME_NAME [flags]
```

### Examples

```

            cli-v2 component list runtime_name
        
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

* [cli-v2 component](cli-v2_component.md)	 - Manage components of Codefresh runtimes

