#!/usr/bin/env bash
if [[ -z "$GIT_REPO" ]]; then
    echo "error: git repo not defined"
    exit 1
fi

if [[ -z "$VERSION" ]]; then
    echo "error: missing VERSION"
    exit 1
fi

echo "$VERSION" > ./dist/version.txt

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "error: GITHUB_TOKEN token not defined"
    exit 1
fi

if [[ -z "$PRERELEASE" ]]; then
    PRERELEASE=false
fi

echo "uploading files:"
ls -1a ./dist/version.txt ./dist/*.tar.gz ./dist/*.sha256 ./manifests/runtime.yaml
echo ""

FILE="./docs/releases/release_notes.md"
echo "using release notes file: ./docs/releases/release_notes.md"
cat $FILE | head -n 5 && echo ...
echo ""

if [[ "$DRY_RUN" == "1" ]]; then
    echo "gh release create --repo $GIT_REPO -t $VERSION -F $FILE --prerelease=$PRERELEASE $VERSION ./dist/version.txt ./dist/*.tar.gz ./dist/*.sha256 ./manifests/runtime.yaml"
    exit 0
fi

gh release create --repo $GIT_REPO -t $VERSION -F $FILE --prerelease=$PRERELEASE $VERSION ./dist/version.txt ./dist/*.tar.gz ./dist/*.sha256 ./manifests/runtime.yaml
