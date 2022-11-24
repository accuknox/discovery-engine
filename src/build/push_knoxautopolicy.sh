#!/bin/bash

AUTOPOL_HOME=`dirname $(realpath "$0")`/../..
cd $AUTOPOL_HOME
AUTOPOL_SRC_HOME=$AUTOPOL_HOME/src

[[ "$REPO" == "" ]] && REPO="accuknox/knoxautopolicy"
[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64"
#[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64,linux/arm64/v8"

[[ "$STABLE_VERSION" != "" ]] && STABLE_LABEL="--label stable-version=$STABLE_VERSION"

# set LABEL
unset LABEL
[[ "$GITHUB_SHA" != "" ]] && LABEL="--label github_sha=$GITHUB_SHA"

# check version
VERSION=`git rev-parse --abbrev-ref HEAD`

if [ ! -z $1 ]; then
    VERSION=$1
fi

echo "[INFO] Pushing $REPO:$VERSION"
docker buildx build --platform $PLATFORMS --push -t $REPO:$VERSION -f $AUTOPOL_SRC_HOME/build/Dockerfile.autopol $STABLE_LABEL $LABEL .

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push $REPO:$VERSION"
    exit 1
fi
echo "[PASSED] Pushed $REPO:$VERSION"
