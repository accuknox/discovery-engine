#!/bin/bash

KNOX_HOME=`dirname $(realpath "$0")`/../..
KNOX_SRC_HOME=$KNOX_HOME/src

cp -r $KNOX_SRC_HOME/libs $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/logging $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/feedconsumer $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/config $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/cluster $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/networkpolicy $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/systempolicy $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/types $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/plugin $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/protobuf $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/server $KNOX_SRC_HOME/build

cp -r $KNOX_SRC_HOME/conf $KNOX_SRC_HOME/build

cp -r $KNOX_SRC_HOME/main.go $KNOX_SRC_HOME/build
cp -r $KNOX_SRC_HOME/go.mod $KNOX_SRC_HOME/build
