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
      --context string           The name of the kubeconfig context to use
      --devel                    use development versions, too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored
      --git-server-crt string    Git Server certificate file
  -t, --git-token string         Your git provider api token [GIT_TOKEN]
  -u, --git-user string          Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                     help for migrate
      --kubeconfig string        Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string         If present, the namespace scope for this CLI request
      --request-timeout string   The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
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

* [cli-v2](cli-v2.md)	 - cli-v2 is used for installing and managing codefresh installations using gitops

