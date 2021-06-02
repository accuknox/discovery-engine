#!/bin/bash

echo "[INFO] Check grpcurl"

if ! command -v grpcurl &> /dev/null
then
    echo "[INFO] grpcurl could not be found"
    exit 1
fi

echo "[PASS] grpcurl is installed"
exit 0

