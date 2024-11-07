## cli-v2 config use-context

Switch the current authentication context

```
cli-v2 config use-context CONTEXT [flags]
```

### Examples

```

# Switch to another authentication context:

        cli-v2 config use-context test
```

### Options

```
  -h, --help   help for use-context
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

* [cli-v2 config](cli-v2_config.md)	 - Manage Codefresh authentication contexts

