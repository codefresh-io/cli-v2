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
      --context string           The name of the kubeconfig context to use
      --devel                    use development versions, too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored
      --fail-condition string    condition to validate [reached | exceeded] (default "exceeded")
  -h, --help                     help for validate-usage
      --kubeconfig string        Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string         If present, the namespace scope for this CLI request
      --request-timeout string   The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
      --subject string           subject to validate [clusters | applications]. All subjects when omitted
  -f, --values string            specify values in a YAML file or a URL
      --version string           specify a version constraint for the chart version to use. This constraint can be a specific tag (e.g. 1.1.1) or it may reference a valid range (e.g. ^2.0.0). If this is not specified, the latest version is used
```

### Options inherited from parent commands

```
      --auth-context string     Run the next command using a specific authentication context
      --cfconfig string         Custom path for authentication contexts config file (default "/home/user")
      --insecure                Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --insecure-ingress-host   Disable certificate validation of ingress host (default: false)
```

### SEE ALSO

* [cli-v2 account](cli-v2_account.md)	 - Account related commands

