### Installed Applications:
* Argo CD [v2.0.4](https://github.com/argoproj/argo-cd/releases/tag/v2.0.4)
  * Argo CD ApplicationSet Controller [2c62537a8e5a](https://github.com/argoproj-labs/applicationset/commit/2c62537a8e5a3d5aecad87b843870789b74bdf89)
* Argo Events [d403c441bc1d](https://github.com/argoproj/argo-events/commit/d403c441bc1d4032daff4e54b496f9342cc5cd57)
* Argo Rollouts [v1.0.2](https://github.com/argoproj/argo-rollouts/releases/tag/v1.0.2)
* Argo Workflows [v3.1.1](https://github.com/argoproj/argo-workflows/releases/tag/v3.1.1)

### Linux
```bash
# get the latest version or change to a specific version
VERSION=$(curl --silent "https://api.github.com/repos/codefresh-io/cli-v2/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/$VERSION/cf-linux-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-* /usr/local/bin/cf

# check the installation
cf version
```

### Mac
```bash
# get the latest version or change to a specific version
VERSION=$(curl --silent "https://api.github.com/repos/codefresh-io/cli-v2/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/$VERSION/cf-darwin-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-* /usr/local/bin/cf

# check the installation
cf version
```
