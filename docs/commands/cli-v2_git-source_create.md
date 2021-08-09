## cli-v2 git-source create

add a new git-source to an existing runtime

```
cli-v2 git-source create runtime_name git-source_name git-src-repo_full_path [flags]
```

### Examples

```

            cli-v2 git-source create runtime_name git-source-name https://github.com/owner/repo-name/my-workflow
        
```

### Options

```
      --git-src-git-token string   Your git provider api token [GIT_SRC_GIT_TOKEN]
      --git-src-provider string    The git provider, one of: gitea|github
      --git-src-repo string        Repository URL [GIT_SRC_GIT_REPO]
  -t, --git-token string           Your git provider api token [GIT_TOKEN]
  -h, --help                       help for create
      --provider string            The git provider, one of: gitea|github
      --repo string                Repository URL [GIT_REPO]
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2 git-source](cli-v2_git-source.md)	 - Manage git-sources of Codefresh runtimes

