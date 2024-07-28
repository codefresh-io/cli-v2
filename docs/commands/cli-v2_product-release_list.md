## cli-v2 product-release list

List all the pipelines

```
cli-v2 product-release list [flags]
```

### Examples

```

            cli-v2 product-release list --product <product>
        
```

### Options

```
  -h, --help                      help for list
      --page int                  page number (default 1)
      --page-limit int            page limit number (default 20)
  -p, --product string            product
      --promotion-flows strings   Filter by promotion flows, comma seperated array
  -s, --status strings            Filter by statuses, comma seperated array RUNNING|SUCCEEDED|SUSPENDED|FAILED
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

* [cli-v2 product-release](cli-v2_product-release.md)	 - Manage product releases of Codefresh account

