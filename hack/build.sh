#!/bin/sh

if [[ ! -z "${GO_FLAGS}" ]]; then
    echo Building \"${OUT_FILE}\" with flags: \"${GO_FLAGS}\" starting at: \"${MAIN}\"
    for d in ${GO_FLAGS}; do
        export $d
    done
fi

go build -ldflags=" \
    -extldflags '-static' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.binaryName=${BINARY_NAME}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.version=${VERSION}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.buildDate=${BUILD_DATE}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.gitCommit=${GIT_COMMIT}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.ArgoCDManifestsURL=${ARGOCD_INSTALLATION_MANIFESTS_URL}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.ArgoEventsManifestsURL=${EVENTS_INSTALLATION_MANIFESTS_URL}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.ArgoRolloutsManifestsURL=${ROLLOUTS_INSTALLATION_MANIFESTS_URL}' \
    -X 'github.com/codefresh-io/cli-v2/pkg/store.ArgoWorkflowsManifestsURL=${WORKFLOWS_INSTALLATION_MANIFESTS_URL}'" \
    -v -o ${OUT_FILE} ${MAIN}