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

## Step 1. Start MySQL database

echo -e "${ORANGE}[INFO] Starting MySQL database${NC}"
start_and_wait_for_mysql_initialization
echo "[INFO] Started MySQL database"

## Step 2. Test coverage

t="/tmp/go-cover.$$.tmp"
cd $AUTOPOL_HOME/src/core; go clean -testcache .; go test -coverprofile=$t $@ && go tool cover -html=$t && unlink $t
cd $AUTOPOL_HOME/src/libs; go clean -testcache .; go test -coverprofile=$t $@ && go tool cover -html=$t && unlink $t
cd $AUTOPOL_HOME/src/plugin; go clean -testcache .; go test -coverprofile=$t $@ && go tool cover -html=$t && unlink $t
cd $AUTOPOL_HOME/src/server; go clean -testcache .; go test -coverprofile=$t $@ && go tool cover -html=$t && unlink $t

if [ $? != 0 ]; then
    echo
    echo "[FAIL] No Coverage"
    exit 1
fi

echo
echo "[PASS] Coverage Generated"

## Step 3. Stop MySQL Database

echo -e "${ORANGE}[INFO] Stopping MySQL database${NC}"
stop_and_wait_for_mysql_termination
echo "[INFO] Stopped MySQL database"