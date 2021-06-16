<p align="center"><img src="./docs/assets/cf.png" alt="Argo Logo"></p>

# Codefresh CLI v2

[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/codefresh-inc/golang%2Fci?type=cf-1)]( https://g.codefresh.io/public/accounts/codefresh-inc/pipelines/new/60ae2ae330acb8f9c9bace7f)
[![codecov](https://codecov.io/gh/codefresh-io/cli-v2/branch/main/graph/badge.svg?token=IDyZNfRUfY)](https://codecov.io/gh/codefresh-io/cli-v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefresh-io/cli-v2)](https://goreportcard.com/report/github.com/codefresh-io/cli-v2)

## Introduction

The new Codefresh CLI tool.

## Installation
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

## Getting Started
