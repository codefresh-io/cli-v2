<p align="center"><img src="./docs/assets/cf.png" alt="Argo Logo"></p>

[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/codefresh-inc/cli-v2%2Frelease?type=cf-1)]( https://g.codefresh.io/public/accounts/codefresh-inc/pipelines/new/60881f8199c9564ef31aac61)
[![codecov](https://codecov.io/gh/codefresh-io/cli-v2/branch/main/graph/badge.svg?token=IDyZNfRUfY)](https://codecov.io/gh/codefresh-io/cli-v2)
[![Documentation Status](https://readthedocs.org/projects/cli-v2/badge/?version=latest)](https://cli-v2.readthedocs.io/en/latest/?badge=latest)
[![slack](https://img.shields.io/badge/slack-codefresh-brightgreen.svg?logo=slack)](https://codefresh.slack.com/archives/C01FG6M5KDY/)

## Introduction

New Codefresh cli tool, using argocd-autopilot

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
