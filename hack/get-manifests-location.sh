#!/bin/bash

REPO="https://github.com/codefresh-io/csdp-official"
BRANCH="$1"

DEFAULT_MANIFESTS_LOCATION="https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
CUSTOM_MANIFESTS_LOCATION="https://github.com/codefresh-io/csdp-official/csdp/hybrid/basic/runtime.yaml?ref=$BRANCH"

git ls-remote --heads ${REPO} ${BRANCH} | grep ${BRANCH} >/dev/null

if [ "$?" == "1" ]; then
	# No matching branch was found in csdp-official
	echo "$DEFAULT_MANIFESTS_LOCATION"
	exit 0
fi

echo "$CUSTOM_MANIFESTS_LOCATION"
