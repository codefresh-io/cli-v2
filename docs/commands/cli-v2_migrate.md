## cli-v2 migrate

migrate a cli-runtime to the new helm-runtime

```
cli-v2 migrate [flags]
```

### Examples

```
cli-v2 helm migrate [RUNTIME_NAME]
```

### Options

```
      --devel                   use development versions, too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored
      --git-server-crt string   Git Server certificate file
  -t, --git-token string        Your git provider api token [GIT_TOKEN]
  -u, --git-user string         Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                    help for migrate
      --version string          specify a version constraint for the chart version to use. This constraint can be a specific tag (e.g. 1.1.1) or it may reference a valid range (e.g. ^2.0.0). If this is not specified, the latest version is used
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

