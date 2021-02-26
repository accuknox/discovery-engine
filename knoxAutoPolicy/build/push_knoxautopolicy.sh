#!/bin/bash

AUTOPOL_HOME=`dirname $(realpath "$0")`/../..
AUTOPOL_SRC_HOME=$AUTOPOL_HOME/knoxAutoPolicy

# check version
VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push accuknox/knoxautopolicy
echo "[INFO] Pushing accuknox/knoxautopolicy:$VERSION"
docker push accuknox/knoxautopolicy:$VERSION

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push accuknox/knoxautopolicy:$VERSION"
    exit 1
else
    echo "[PASSED] Pushed accuknox/knoxautopolicy:$VERSION"
    exit 0
fi
