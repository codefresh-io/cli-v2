#!/bin/bash

REPO="https://github.com/codefresh-io/csdp-official"
BRANCH="$1"

DEFAULT_MANIFESTS_LOCATION="https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
RUNTIME_DEFINITION_URL="https://raw.githubusercontent.com/codefresh-io/csdp-official/$BRANCH/csdp/hybrid/basic/runtime.yaml"
RUNTIME_DEFINITION_FILE="/codefresh/volume/runtime.yaml"

git ls-remote --heads ${REPO} ${BRANCH} | grep ${BRANCH} >/dev/null

if [ "$?" == "1" ]; then
	# No matching branch was found in csdp-official
	curl --silent "$DEFAULT_MANIFESTS_LOCATION" > $RUNTIME_DEFINITION_FILE
	echo $RUNTIME_DEFINITION_FILE
	exit 0
fi

curl --silent "$RUNTIME_DEFINITION_URL" | yq "(.spec.components[] | select(.type == \"kustomize\") | .url) += \"?ref=$BRANCH\"" | yq ".spec.bootstrapSpecifier += \"?ref=$BRANCH\"" > $RUNTIME_DEFINITION_FILE
echo $RUNTIME_DEFINITION_FILE
