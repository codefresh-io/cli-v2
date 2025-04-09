## cli-v2 git-source create

Adds a new git-source to an existing runtime

```
cli-v2 git-source create RUNTIME_NAME GITSOURCE_NAME [flags]
```

### Examples

```

            cli-v2 git-source create runtime_name git-source-name --git-src-repo https://github.com/owner/repo-name/my-workflow
        
```

### Options

```
      --create-repo           If true, will create the specified git-source repo in case it doesn't already exist
      --exclude string        files to exclude. can be either filenames or a glob
      --git-src-repo string   Repository URL [%sGIT_SOURCE_GIT_REPO]
  -h, --help                  help for create
      --include string        files to include. can be either filenames or a glob
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

* [cli-v2 git-source](cli-v2_git-source.md)	 - Manage git-sources of Codefresh runtimes

