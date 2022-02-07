## cli-v2 config get-runtime

Gets the default runtime for the current authentication context

```
cli-v2 config get-runtime [flags]
```

### Examples

```

# Prints the default runtime:

        cli-v2 config get-runtime
```

### Options

```
  -h, --help   help for get-runtime
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

