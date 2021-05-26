<p align="center"><img src="./docs/assets/cf.png" alt="Argo Logo"></p>

# Codefresh CLI v2

[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/codefresh-inc/cli-v2%2Fci?type=cf-1&key=eyJhbGciOiJIUzI1NiJ9.NTY3MmQ4ZGViNjcyNGI2ZTM1OWFkZjYy.AN2wExsAsq7FseTbVxxWls8muNx_bBUnQWQVS8IgDTI)]( https://g.codefresh.io/pipelines/edit/new/builds?id=60ae2ae330acb8f9c9bace7f&pipeline=ci&projects=cli-v2&projectId=60ae2a8498763b36c241d563)
[![codecov](https://codecov.io/gh/codefresh-io/cli-v2/branch/main/graph/badge.svg?token=IDyZNfRUfY)](https://codecov.io/gh/codefresh-io/cli-v2)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/codefresh-io/cli-v2)
![GitHub all releases](https://img.shields.io/github/downloads/codefresh-io/cli-v2/total)

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
