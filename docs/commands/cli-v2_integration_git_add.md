## cli-v2 integration git add

Add a new git integration

```
cli-v2 integration git add [NAME] [flags]
```

### Options

```
      --account-admins-only   If true, this integration would only be visible to account admins (default: false)
      --api-url string        Git provider API Url
  -h, --help                  help for add
      --provider string       One of bitbucket|bitbucket-server|github|gitlab (default "github")
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --insecure-ingress-host      Disable certificate validation of ingress host (default: false)
      --request-timeout duration   Request timeout (default 30s)
      --runtime string             Name of runtime to use
```

### SEE ALSO

* [cli-v2 integration git](cli-v2_integration_git.md)	 - Manage your git integrations

