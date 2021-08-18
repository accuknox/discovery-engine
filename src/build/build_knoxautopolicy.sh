#!/bin/bash

AUTOPOL_HOME=`dirname $(realpath "$0")`/../..
AUTOPOL_SRC_HOME=$AUTOPOL_HOME/src

# check version

VERSION=dev

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images
docker images | grep knoxautopolicy | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null
echo "[INFO] Removed existing accuknox/knoxautopolicy images"

# remove old files (just in case)
$AUTOPOL_SRC_HOME/build/clean_source_files.sh
echo "[INFO] Removed source files just in case"

# copy files to build
$AUTOPOL_SRC_HOME/build/copy_source_files.sh
echo "[INFO] Copied new source files"

# build image
echo "[INFO] Building accuknox/knoxautopolicy:$VERSION"
docker build -t accuknox/knoxautopolicy:$VERSION . -f $AUTOPOL_SRC_HOME/build/Dockerfile.autopol

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build accuknox/knoxautopolicy:$VERSION"
    # remove old files
    $AUTOPOL_SRC_HOME/build/clean_source_files.sh
    exit 1
else
    echo "[PASSED] Built accuknox/knoxautopolicy:$VERSION"
fi

# remove old files
$AUTOPOL_SRC_HOME/build/clean_source_files.sh
