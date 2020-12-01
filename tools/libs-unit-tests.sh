#!/bin/bash

AUTOPOL_HOME=`dirname $(realpath "$0")`/..

cd $AUTOPOL_HOME/src/libs
go test

cd $AUTOPOL_HOME
