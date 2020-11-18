#!/bin/bash

KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

DB_DRIVER=mongodb
DB_PORT=27017
DB_USER=root
DB_PASS=password
DB_NAME=flow_management

COL_NETWORK_FLOW=network_flow
COL_DISCOVERED_POLICY=discovered_policy

$KNOX_AUTO_HOME/src/knoxAutoPolicy
