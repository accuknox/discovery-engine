#!/bin/bash

KNOX_HOME=`dirname $(realpath "$0")`/../..
KNOX_SRC_HOME=$KNOX_HOME/src

rm -r $KNOX_SRC_HOME/build/libs
rm -r $KNOX_SRC_HOME/build/core
rm -r $KNOX_SRC_HOME/build/types
rm -r $KNOX_SRC_HOME/build/plugin
rm -r $KNOX_SRC_HOME/build/protobuf
rm -r $KNOX_SRC_HOME/build/server
rm -r $KNOX_SRC_HOME/build/main.go
rm -r $KNOX_SRC_HOME/build/go.mod

