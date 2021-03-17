#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

AUTOPOL_HOME=`dirname $(realpath "$0")`/..
AUTOPOL_POLICY=$AUTOPOL_HOME/policies
AUTOPOL_SRC_HOME=$AUTOPOL_HOME/src

TEST_HOME=`dirname $(realpath "$0")`
TEST_SCRIPTS=`dirname $(realpath "$0")`/scripts

PASSED_TESTS=()
FAILED_TESTS=()
COUNT_TESTS=0

## ==================== ##   
## == KnoxAutoPolicy == ##
## ==================== ##

res_start_service=0

function start_and_wait_for_KnoxAutoPolicy_initialization() {
    $AUTOPOL_HOME/scripts/startService.sh &> /dev/null &
    if [ $? != 0 ]; then
        res_start_service=1
        exit 1
    fi

    sleep 1
    
    LISTEN=$(ps -e | grep knoxAutoPolicy | wc -l)
    if [ $LISTEN != 1 ]; then
        res_start_service=1
        exit 1
    fi
}

function stop_and_wait_for_KnoxAutoPolicy_termination() {
    ps -e | grep knoxAutoPolicy | awk '{print $1}' | xargs -I {} kill {}

    for (( ; ; ))
    do
        ps -e | grep knoxAutoPolicy &> /dev/null
        if [ $? != 0 ]; then
            break
        fi

        sleep 1
    done
}

function replace_discovery_mode() {
    if [[ $1 == *"_egress_ingress_"* ]]; then
        sed -i "s/DISCOVERY_POLICY_TYPES=1/DISCOVERY_POLICY_TYPES=3/" $AUTOPOL_HOME/scripts/startService.sh
        sed -i "s/DISCOVERY_POLICY_TYPES=2/DISCOVERY_POLICY_TYPES=3/" $AUTOPOL_HOME/scripts/startService.sh
    elif [[ $1 == *"_egress_"* ]]; then
        sed -i "s/DISCOVERY_POLICY_TYPES=2/DISCOVERY_POLICY_TYPES=1/" $AUTOPOL_HOME/scripts/startService.sh
        sed -i "s/DISCOVERY_POLICY_TYPES=3/DISCOVERY_POLICY_TYPES=1/" $AUTOPOL_HOME/scripts/startService.sh
    else
        sed -i "s/DISCOVERY_POLICY_TYPES=1/DISCOVERY_POLICY_TYPES=2/" $AUTOPOL_HOME/scripts/startService.sh
        sed -i "s/DISCOVERY_POLICY_TYPES=3/DISCOVERY_POLICY_TYPES=2/" $AUTOPOL_HOME/scripts/startService.sh
    fi
}

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

## ================== ##
## == Microservice == ##
## ================== ##

function apply_and_wait_for_microservice_creation() {
    cd $TEST_HOME/$1/deployment_k8s

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply multiubuntu${NC}"
        res_microservice=1
        return
    fi

    for (( ; ; ))
    do
        RAW=$(kubectl get pods -n multiubuntu | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n multiubuntu | grep Running | wc -l`

        if [ $ALL == $READY ]; then
            break
        fi

        sleep 1
    done
}

function delete_and_wait_for_microserivce_deletion() {
    cd $TEST_HOME/$1/deployment_k8s

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete multiubuntu${NC}"
        res_delete=1
    fi
}

## ==================== ##
## == Test Functions == ##
## ==================== ##

function add_label_pods() {
    if [[ $2 == "TC_16" ]] || [[ $2 == "TC_30" ]]; then
        cd $1
        /bin/bash ./add_label.sh $> /dev/null
    fi
}

function del_label_pods() {
    if [[ $2 == "TC_16" ]] || [[ $2 == "TC_30" ]]; then
        cd $1
        /bin/bash ./del_label.sh $> /dev/null
    fi
}

function run_test_case() {
    cd $1

    ACTUAL_YAML_FILE=cilium_policies_$2.yaml

    for JSON_FILE in $(ls -r $TC_*.json)
    do
        for EXPECTED_YAML_FILE in $(ls -r $TC_*.yaml)
        do
            # check before / after
            if [[ $JSON_FILE == *"before"* ]] && [[ $EXPECTED_YAML_FILE != *"before"* ]]; then
                continue
            elif [[ $JSON_FILE == *"after"* ]] && [[ $EXPECTED_YAML_FILE != *"after"* ]]; then
                continue
            fi

            echo -e "${GREEN}[INFO] Discovering from $JSON_FILE"
            if [[ $JSON_FILE == *"after"* ]]; then
                $TEST_SCRIPTS/startTest.sh $1/$JSON_FILE &> /dev/null
            else
                $TEST_SCRIPTS/startTest.sh $1/$JSON_FILE clear &> /dev/null
            fi

            if [ $? != 0 ]; then
                echo -e "${RED}[FAIL] Failed to discover policies from $JSON_FILE${NC}"
                res_case=1
                return
            fi
            echo "[INFO] Discovered policies from $JSON_FILE"

            echo -e "${GREEN}[INFO] Comparing $EXPECTED_YAML_FILE and $ACTUAL_YAML_FILE${NC}"
            python3 $TEST_SCRIPTS/diff.py $AUTOPOL_POLICY/$ACTUAL_YAML_FILE $1/$EXPECTED_YAML_FILE
            if [ $? != 0 ]; then
                echo -e "${RED}[FAIL] Failed $3${NC}"
                FAILED_TESTS+=($testcase)
                return
            fi
        done
    done

    echo -e "${BLUE}[PASS] Passed $3${NC}"
    PASSED_TESTS+=($testcase)
}

## ==================== ##
## == Test Procedure == ##
## ==================== ##

## Step 1. Build KnoxAutoPolicy

cd $AUTOPOL_SRC_HOME

if [ ! -f KnoxAutoPolicy ]; then
    echo -e "${ORANGE}[INFO] Building KnoxAutoPolicy${NC}"
    make clean > /dev/null ; make > /dev/null
    echo "[INFO] Built KnoxAutoPolicy"
fi

## Step 2. Start MySQL database

echo -e "${ORANGE}[INFO] Starting MySQL database${NC}"
start_and_wait_for_mysql_initialization
echo "[INFO] Started MySQL database"

## Step 3. Deploy microservice

microservice=multiubuntu

res_microservice=0
echo -e "${ORANGE}[INFO] Applying $microservice${NC}"
apply_and_wait_for_microservice_creation $microservice

if [ $res_microservice == 0 ]; then
    echo "[INFO] Applied $microservice"

    echo "[INFO] Wait for initialization"
    sleep 30
    echo "[INFO] Started to run testcases"

## Step 4. Run all the test cases
    cd $TEST_HOME/$microservice/test-cases
    for testcase in $(ls -d $TC_*)
    do
        add_label_pods $TEST_HOME/$microservice/test-cases/$testcase $testcase

        # replace configuration
        JSON_FILE=$(ls $TEST_HOME/$microservice/test-cases/$testcase/*.json)
        replace_discovery_mode $JSON_FILE

        # start knoxAutoPolicy
        echo -e "${ORANGE}[INFO] Starting KnoxAutoPolicy${NC}"
        start_and_wait_for_KnoxAutoPolicy_initialization
        if [ $res_start_service != 0 ]; then
            echo -e "${RED}[FAIL] Failed to start KnoxAutoPolicy${NC}"
            exit 1
        else
            echo "[INFO] Started KnoxAutoPolicy"
        fi

        # run a test case
        res_case=0
        echo -e "${ORANGE}[INFO] Testing $testcase${NC}"
        run_test_case $TEST_HOME/$microservice/test-cases/$testcase $microservice $testcase
        if [ $res_case != 0 ]; then
            echo "[INFO] Not tested $testcase"
        else
            echo "[INFO] Tested $testcase"
            ((COUNT_TESTS++))
        fi

        # stop knoxAutoPolicy
        echo -e "${ORANGE}[INFO] Stopping KnoxAutoPolicy${NC}"
        stop_and_wait_for_KnoxAutoPolicy_termination
        echo "[INFO] Stopped KnoxAutoPolicy"

        del_label_pods $TEST_HOME/$microservice/test-cases/$testcase $testcase
    done

## Step 6. Delete Microservice
    res_delete=0
    echo -e "${ORANGE}[INFO] Deleting $microservice${NC}"
    delete_and_wait_for_microserivce_deletion $microservice
    if [ $res_delete == 0 ]; then
        echo "[INFO] Deleted $microservice"
    fi
fi

## Step 7. Stop MySQL Database

echo -e "${ORANGE}[INFO] Stopping MySQL database${NC}"
stop_and_wait_for_mysql_termination
echo "[INFO] Stopped MySQL database"

## Step 8. Show Test Results

echo ""
echo -e "${ORANGE}[INFO] Test Results${NC}"
echo "       - Completed Cases: " $COUNT_TESTS
echo "       - Passed    Cases: " ${#PASSED_TESTS[@]}
echo -n "       - Failed    Cases: " ${#FAILED_TESTS[@]}

if (( ${#FAILED_TESTS[@]} > 0 )); then
    echo -n " ("
    for casenumber in ${FAILED_TESTS[@]}
    do
        echo -n " "$casenumber
    done
    echo ")"
fi

echo ""