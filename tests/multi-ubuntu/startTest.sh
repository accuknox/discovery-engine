#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/../..

if [ -z $1 ]; then
    echo "Usage: $0 [json file] | $0 [json file] dbclear"
    echo ""
    echo "Example: ./startTest.sh /home/sslee/knoxAutoPolicy/tests/multi-ubuntu/prepared-flows/flows.json"
    exit
fi

JSON_FILE=$1

DATA='{"req": "dbclear", "logfile": "'$1'"}'
if [ -z $2 ]; then # if no dbclear,
    DATA='{"logfile": "'$1'"}'
fi

grpcurl -plaintext -d "$DATA" localhost:9089 v1.worker.Worker.Start
