## cli-v2

cli-v2 is used for installing and managing codefresh installations using gitops

### Synopsis

cli-v2 is used for installing and managing codefresh installations using gitops.
        
Most of the commands in this CLI require you to specify a personal access token
for your git provider. This token is used to authenticate with your git provider
when performing operations on the gitops repository, such as cloning it and
pushing changes to it.

It is recommended that you export the $GIT_TOKEN and $GIT_REPO environment
variables in advanced to simplify the use of those commands.


```
cli-v2 [flags]
```

### Options

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
  -h, --help                       help for cli-v2
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2 config](cli-v2_config.md)	 - Manage Codefresh authentication contexts
* [cli-v2 runtime](cli-v2_runtime.md)	 - Manage Codefresh runtimes
* [cli-v2 version](cli-v2_version.md)	 - Show cli version

