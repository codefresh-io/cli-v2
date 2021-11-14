## cli-v2 config set-runtime

Sets the default runtime name to use for the current authentication context

```
cli-v2 config set-runtime RUNTIME [flags]
```

### Examples

```

# Sets the default runtime to 'runtime-2':

        cli-v2 config set-runtime runtime-2
```

### Options

```
  -h, --help   help for set-runtime
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2 config](cli-v2_config.md)	 - Manage Codefresh authentication contexts

