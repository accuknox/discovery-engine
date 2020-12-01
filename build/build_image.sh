#!/bin/bash

#if [[ -z "${GITHUB_TOKEN}" ]]; then
 #  echo "we need GITHUB_TOKEN env to access private repo"
  # exit -1
#fi

# remove old images
docker images | grep knox-auto-policy | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

KNOX_HOME=`dirname $(realpath "$0")`/..
KNOX_SRC_HOME=$KNOX_HOME/src

cp -r $KNOX_SRC_HOME/libs $KNOX_HOME/build/
cp -r $KNOX_SRC_HOME/core $KNOX_HOME/build/
cp -r $KNOX_SRC_HOME/types $KNOX_HOME/build/
cp -r $KNOX_SRC_HOME/main.go $KNOX_HOME/build/
cp -r $KNOX_SRC_HOME/go.mod $KNOX_HOME/build/

#docker build --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t image.0x010.com/knox-auto-policy:latest . -f $KNOX_HOME/build/Dockerfile.autopol
docker build -t knox-auto-policy:latest . -f $KNOX_HOME/build/Dockerfile.autopol

rm -r $KNOX_HOME/build/libs
rm -r $KNOX_HOME/build/core
rm -r $KNOX_HOME/build/types
rm -r $KNOX_HOME/build/main.go
rm -r $KNOX_HOME/build/go.mod
