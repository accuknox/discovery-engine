#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

AUTOPOL_HOME=`dirname $(realpath "$0")`/..
TEST_HOME=`dirname $(realpath "$0")`

## ============== ##
## == Database == ##
## ============== ##

function start_and_wait_for_mysql_initialization() {
    cd $TEST_HOME/mysql
    docker-compose up -d

    for (( ; ; ))
    do
        docker logs mysql-example > ./logs 2>&1
        log=$(cat $TEST_HOME/mysql/logs)
        if [[ $log == *"Ready for start up"* ]]; then
            break
        fi

        sleep 1
    done
}

function stop_and_wait_for_mysql_termination() {
    cd $TEST_HOME/mysql
    docker-compose down -v
    rm $TEST_HOME/mysql/logs
}

## Test go unit

cd $AUTOPOL_HOME/src

echo
echo -e "${ORANGE}[INFO] Run go-unit test knoxAutoPolicy${NC}"
echo

make test

if [ $? != 0 ]; then
    echo
    echo "[FAIL] Failed to go-unit test KnoxAutoPolicy"
    exit 1
fi

echo
echo "[PASS] Tested go-unit knoxAutoPolicy"