## cli-v2 product-release list

List all product releases

```
cli-v2 product-release list [flags]
```

### Examples

```

            cli-v2 product-release list <product-name>
            cli-v2 product-release list <product-name> --page-limit 3
            cli-v2 product-release list <product-name> --status RUNNING,FAILED --promotion-flows base-flow,flow-2
        
```

### Options

```
  -h, --help                      help for list
      --page-limit int            page limit number, limited to 50 (default 20)
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

