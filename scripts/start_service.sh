#!/bin/bash

export AUTOPOL_HOME=`dirname $(realpath "$0")`/..
export CONF_FILE_NAME=local

$AUTOPOL_HOME/src/knoxAutoPolicy -config-path=$AUTOPOL_HOME/src/conf
echo $?
if [ $? != 0 ]; then
    exit 1
fi
