### Installed Applications:

-   Argo CD [v2.1.5](https://github.com/codefresh-io/argo-cd/releases/tag/v2.1.3)
    -   Argo CD ApplicationSet Controller [v0.2.0](https://github.com/argoproj-labs/applicationset/releases/tag/v0.2.0)
-   Argo Events [v1.5.5](https://github.com/argoproj/argo-events/releases/tag/v1.4.0)
-   Argo Rollouts [v1.1.0](https://github.com/argoproj/argo-rollouts/releases/tag/v1.1.0)
-   Argo Workflows [v3.2.4](https://github.com/argoproj/argo-workflows/releases/tag/v3.1.8)

### Using brew:

```bash
# tap Codefresh homebrew repo
brew tap codefresh-io/cli

# install cf2 CLI
brew install cf2

# check the installation
cf version
```

### Linux

```bash
# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.0.212/cf-linux-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-linux-amd64 /usr/local/bin/cf

# check the installation
cf version
```

### Mac

```bash
# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.0.212/cf-darwin-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-darwin-amd64 /usr/local/bin/cf

# check the installation
cf version
```
