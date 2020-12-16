#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

export DB_DRIVER=mysql
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management
export DB_HOST=127.0.0.1

export TB_NETWORK_FLOW=network_flow
export TB_DISCOVERED_POLICY=discovered_policy

export OUT_DIR=$KNOX_AUTO_HOME/policies/

# egress | ingress | egress+ingress
export DISCOVERY_MODE=egress+ingress

# hubble | db
export NETWORK_LOG_FROM=db

# cilium hubble info
export HUBBLE_URL=127.0.0.1
export HUBBLE_PORT=4245

$KNOX_AUTO_HOME/src/knoxAutoPolicy
