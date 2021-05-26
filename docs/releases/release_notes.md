### Linux
```bash
# get the latest version or change to a specific version
VERSION=$(curl --silent "https://api.github.com/repos/codefresh-io/cli-v2/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/$VERSION/cli-v2-linux-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cli-v2-* /usr/local/bin/cli-v2

# check the installation
cli-v2 version
```

### Mac
```bash
# get the latest version or change to a specific version
VERSION=$(curl --silent "https://api.github.com/repos/codefresh-io/cli-v2/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

# download and extract the binary
curl -L --output - https://github.com/codefresh-io/cli-v2/releases/download/$VERSION/cli-v2-darwin-amd64.tar.gz | tar zx

# move the binary to your $PATH
mv ./cli-v2-* /usr/local/bin/cli-v2

# check the installation
cli-v2 version
```
