## cli-v2 git-source delete

delete a git-source from a runtime

```
cli-v2 git-source delete RUNTIME_NAME GITSOURCE_NAME [flags]
```

### Examples

```

            cli-v2 git-source delete runtime_name git-source_name 
        
```

### Options

```
  -h, --help   help for delete
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

* [cli-v2 git-source](cli-v2_git-source.md)	 - Manage git-sources of Codefresh runtimes

