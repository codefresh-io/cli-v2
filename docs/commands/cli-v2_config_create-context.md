## cli-v2 config create-context

Create a new Codefresh authentication context

```
cli-v2 config create-context NAME [flags]
```

### Examples

```

# Create a new context named 'test':

        cli-v2 config create-context test --api-key TOKEN
```

### Options

```
      --api-key string   API key
      --ca-cert string   Codefresh Platform certificate file (for on-prem)
  -h, --help             help for create-context
      --url string       Codefresh system custom url  (default "https://g.codefresh.io")
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

