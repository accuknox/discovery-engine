#!/bin/bash

#if [[ -z "${GITHUB_TOKEN}" ]]; then
 #  echo "we need GITHUB_TOKEN env to access private repo"
  # exit -1
#fi

# remove old images
docker images | grep knox-auto-policy | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

KNOX_HOME=`dirname $(realpath "$0")`/../..
KNOX_SRC_HOME=$KNOX_HOME/src

cp -r $KNOX_SRC_HOME/libs $KNOX_HOME/deployments/build_image
cp -r $KNOX_SRC_HOME/core $KNOX_HOME/deployments/build_image
cp -r $KNOX_SRC_HOME/types $KNOX_HOME/deployments/build_image
cp -r $KNOX_SRC_HOME/plugin $KNOX_HOME/deployments/build_image
cp -r $KNOX_SRC_HOME/main.go $KNOX_HOME/deployments/build_image
cp -r $KNOX_SRC_HOME/go.mod $KNOX_HOME/deployments/build_image

docker build -t knoxautopolicy:latest . -f Dockerfile.autopol

rm -r $KNOX_HOME/deployments/build_image/libs
rm -r $KNOX_HOME/deployments/build_image/core
rm -r $KNOX_HOME/deployments/build_image/types
rm -r $KNOX_HOME/deployments/build_image/plugin
rm -r $KNOX_HOME/deployments/build_image/main.go
rm -r $KNOX_HOME/deployments/build_image/go.mod
