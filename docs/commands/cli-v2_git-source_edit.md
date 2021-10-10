## cli-v2 git-source edit

edit a git-source of a runtime

```
cli-v2 git-source edit runtime_name git-source_name [flags]
```

### Examples

```

            cli-v2 git-source edit runtime_name git-source_name --git-src-repo https://github.com/owner/repo-name/my-workflow
        
```

### Options

```
      --git-src-git-token string   Your git provider api token [GIT_SRC_GIT_TOKEN]
      --git-src-git-user string    Your git provider user name [GIT_SRC_GIT_USER] (not required in GitHub)
      --git-src-provider string    The git provider, one of: gitea|github
      --git-src-repo string        Repository URL [GIT_SRC_GIT_REPO]
  -t, --git-token string           Your git provider api token [GIT_TOKEN]
  -u, --git-user string            Your git provider user name [GIT_USER] (not required in GitHub)
  -h, --help                       help for edit
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

