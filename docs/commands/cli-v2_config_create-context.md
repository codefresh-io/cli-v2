## cli-v2 config create-context

Create a new Codefresh authentication context

```
cli-v2 config create-context [flags]
```

### Examples

```

# Create a new context named 'test':

        cli-v2 config create-context test --api-key TOKEN
```

### Options

```
      --api-key string   API key
  -h, --help             help for create-context
      --url string       Codefresh system custom url  (default "https://g.codefresh.io")
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

