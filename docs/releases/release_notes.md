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
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.2.11/cf-linux-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-linux-amd64 /usr/local/bin/cf

# check the installation
cf version
```

### Mac

```bash
# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/v0.2.11/cf-darwin-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cf-darwin-amd64 /usr/local/bin/cf

# check the installation
cf version
```
