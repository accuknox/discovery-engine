#!/bin/bash

KNOX_HOME=`dirname $(realpath "$0")`/../..
KNOX_SRC_HOME=$KNOX_HOME/knoxAutoPolicy

cp -r $KNOX_SRC_HOME/libs $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/core $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/types $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/plugin $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/protobuf $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/server $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/main.go $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/go.mod $KNOX_SRC_HOME/build
