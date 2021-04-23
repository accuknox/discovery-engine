#!/bin/bash

KNOX_HOME=`dirname $(realpath "$0")`/../..
KNOX_SRC_HOME=$KNOX_HOME/src

rm -r $KNOX_SRC_HOME/build/libs > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/logging > /dev/null 2>&1 
rm -r $KNOX_SRC_HOME/build/feedconsumer > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/core > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/types > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/plugin > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/protobuf > /dev/null 2>&1
rm -r $KNOX_SRC_HOME/build/server > /dev/null 2>&1

rm -r $KNOX_SRC_HOME/build/conf > /dev/null 2>&1

rm -r $KNOX_SRC_HOME/build/main.go > /dev/null 2>&1 
rm -r $KNOX_SRC_HOME/build/go.mod > /dev/null 2>&1

