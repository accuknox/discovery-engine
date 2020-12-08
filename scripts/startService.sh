#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

export DB_DRIVER=mongodb
export DB_PORT=27017
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management

export COL_NETWORK_FLOW=network_flow
export COL_DISCOVERED_POLICY=discovered_policy

export OUT_DIR=$KNOX_AUTO_HOME/policies/

export DISCOVERY_MODE=Ingress

$KNOX_AUTO_HOME/src/knoxAutoPolicy
