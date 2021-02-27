#!/bin/bash

AUTOPOL_HOME=`dirname $(realpath "$0")`/..

cd $AUTOPOL_HOME/knoxAutoPolicy

## == ##

echo
echo "[INFO] Test KnoxAutoPolicy"
echo

make test

if [ $? != 0 ]; then
    echo
    echo "[FAIL] Failed to test KnoxAutoPolicy"
    exit 1
fi

echo
echo "[PASS] Tested KnoxAutoPolicy"