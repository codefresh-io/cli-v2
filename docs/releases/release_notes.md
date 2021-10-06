### Installed Applications:
* Argo CD [v2.1.0-rc2](https://github.com/codefresh-io/argo-cd/releases/tag/v2.1.0-rc2)
  * Argo CD ApplicationSet Controller [2c62537a8e5a](https://github.com/argoproj-labs/applicationset/commit/2c62537a8e5a3d5aecad87b843870789b74bdf89)
* Argo Events [v1.4.0](https://github.com/argoproj/argo-events/releases/tag/v1.4.0)
* Argo Rollouts [v1.0.6](https://github.com/argoproj/argo-rollouts/releases/tag/v1.0.6)
* Argo Workflows [v3.1.8](https://github.com/argoproj/argo-workflows/releases/tag/v3.1.8)

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
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.0.115/cf-linux-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-linux-amd64 /usr/local/bin/cf

# check the installation
cf version
```

### Mac
```bash
# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.0.115/cf-darwin-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-darwin-amd64 /usr/local/bin/cf

# check the installation
cf version
```