## cli-v2 config update-gitops-settings

Updates the account's GitOps settings (gitProvider|gitApiUrl|sharedConfigRepo) if possible

```
cli-v2 config update-gitops-settings [flags]
```

### Options

```
      --git-api-url string          Your git server's API URL
      --git-provider ProviderType   The git provider, one of: bitbucket|bitbucket-server|github|gitlab
  -h, --help                        help for update-gitops-settings
      --shared-config-repo string   URL to the shared configurations repo
      --silent                      Disables the command wizard
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

