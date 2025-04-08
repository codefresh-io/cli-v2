#!/usr/bin/env bash

if [[ ! -z "${GO_FLAGS}" ]]; then
    echo Building \"${OUT_FILE}\" with flags: \"${GO_FLAGS}\" starting at: \"${MAIN}\"
    for d in ${GO_FLAGS}; do
        export $d
    done
fi

go build -ldflags=" \
    -extldflags '-static' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.binaryName=${BINARY_NAME}' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.version=${VERSION}' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.buildDate=${BUILD_DATE}' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.gitCommit=${GIT_COMMIT}' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.AddClusterDefURL=${ADD_CLUSTER_DEF_URL}' \
    -X 'github.com/codefresh-io/cli-v2/internal/store.SegmentWriteKey=${SEGMENT_WRITE_KEY}'" \
    -v -o ${OUT_FILE} ${MAIN}
