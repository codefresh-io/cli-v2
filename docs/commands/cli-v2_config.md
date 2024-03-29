## cli-v2 config

Manage Codefresh authentication contexts

### Synopsis

By default, Codefresh authentication contexts are persisted at $HOME/.cfconfig.
You can create, delete and list authentication contexts using the following
commands, respectively:

        cli-v2 config create-context <NAME> --api-key <key>

        cli-v2 config delete-context <NAME>

        cli-v2 config get-contexts


```
cli-v2 config [flags]
```

### Options

```
  -h, --help   help for config
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
* [cli-v2 config create-context](cli-v2_config_create-context.md)	 - Create a new Codefresh authentication context
* [cli-v2 config current-context](cli-v2_config_current-context.md)	 - Shows the currently selected Codefresh authentication context
* [cli-v2 config delete-context](cli-v2_config_delete-context.md)	 - Delete the specified authentication context
* [cli-v2 config get-contexts](cli-v2_config_get-contexts.md)	 - Lists all Codefresh authentication contexts
* [cli-v2 config get-runtime](cli-v2_config_get-runtime.md)	 - Gets the default runtime for the current authentication context
* [cli-v2 config set-runtime](cli-v2_config_set-runtime.md)	 - Sets the default runtime name to use for the current authentication context
* [cli-v2 config update-gitops-settings](cli-v2_config_update-gitops-settings.md)	 - Updates the account's GitOps settings (gitProvider|gitApiUrl|sharedConfigRepo) if possible
* [cli-v2 config use-context](cli-v2_config_use-context.md)	 - Switch the current authentication context

