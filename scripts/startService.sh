#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

# database info
export DB_DRIVER=mysql
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management
export DB_HOST=127.0.0.1

# table info
export TB_NETWORK_FLOW=network_flow
export TB_DISCOVERED_POLICY=discovered_policy

# output dir info
export OUT_DIR=$KNOX_AUTO_HOME/policies/

# available discovery modes: egress | ingress | egress+ingress
export DISCOVERY_MODE=egress+ingress

# available network log source: hubble | db
export NETWORK_LOG_FROM=db

# cilium hubble info (if connect to hubble directly)
export HUBBLE_URL=127.0.0.1
export HUBBLE_PORT=4245

# operation mode: c=cronjob | a=at once
if [ $# -eq 1 ]
  then
    export OPERATION_MODE=$1
fi

$KNOX_AUTO_HOME/src/knoxAutoPolicy
