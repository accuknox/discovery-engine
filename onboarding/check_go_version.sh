#!/bin/bash

echo "[INFO] Check Go Version (>= 1.15.0)"

if ! command -v go &> /dev/null
then
    echo "[INFO] go could not be found"
    exit 1
fi

VER=`go version | { read _ _ v _; echo ${v#go}; }`
MAJOR=`echo $VER | cut -d. -f1`
MINOR=`echo $VER | cut -d. -f2`

if [ $MAJOR -le 0 ]; then
    echo "[FAIL] $VER is installed"
    exit 1
elif [ $MAJOR -eq 1 ]; then
    if [ $MINOR -lt 15 ]; then
        echo "[FAIL] $VER is installed"
        exit 1
    fi
fi

echo "[PASS] $VER is installed"
exit 0

