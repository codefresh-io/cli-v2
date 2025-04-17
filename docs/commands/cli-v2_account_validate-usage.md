## cli-v2 account validate-usage

Validate usage of account resources

```
cli-v2 account validate-usage [flags]
```

### Examples

```
cli-v2 account validate-usage
```

### Options

```
      --fail-condition string   condition to validate [reached | exceeded] (default "exceeded")
  -h, --help                    help for validate-usage
      --subject string          subject to validate [clusters | applications]. All subjects when omitted
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

* [cli-v2 account](cli-v2_account.md)	 - Account related commands

