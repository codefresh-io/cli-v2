#!/bin/sh

if [[ ! -z "${GO_FLAGS}" ]]; then
    echo Building \"${OUT_FILE}\" with flags: \"${GO_FLAGS}\" starting at: \"${MAIN}\"
    for d in ${GO_FLAGS}; do
        export $d
    done
fi

${PACKR_CMD} build -ldflags=" \
    -extldflags '-static' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.binaryName=${BINARY_NAME}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.version=${VERSION}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.buildDate=${BUILD_DATE}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.gitCommit=${GIT_COMMIT}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.installationManifestsURL=${INSTALLATION_MANIFESTS_URL}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.installationManifestsNamespacedURL=${INSTALLATION_MANIFESTS_NAMESPACED_URL}'" \
    -v -o ${OUT_FILE} ${MAIN}