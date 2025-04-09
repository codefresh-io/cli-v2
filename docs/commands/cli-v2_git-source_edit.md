## cli-v2 git-source edit

edit a git-source of a runtime

```
cli-v2 git-source edit RUNTIME_NAME GITSOURCE_NAME [flags]
```

### Examples

```

            cli-v2 git-source edit runtime_name git-source_name --git-src-repo https://github.com/owner/repo-name.git/path/to/dir
        
```

### Options

```
      --exclude string        files to exclude. can be either filenames or a glob
      --git-src-repo string   Repository URL [%sGIT_SOURCE_GIT_REPO]
  -h, --help                  help for edit
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

