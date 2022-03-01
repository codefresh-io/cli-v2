## cli-v2 completion

Generates shell completion script.

### Synopsis

Generates shell completion script for your shell environment

Example:

    source <(cli-v2 completion bash)


```
cli-v2 completion [bash|zsh|fish|powershell] [flags]
```

### Options

```
  -h, --help   help for completion
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

* [cli-v2](cli-v2.md)	 - cli-v2 is used for installing and managing codefresh installations using gitops

