#!/bin/bash

echo "Input requested parameters for fetching observability data."
echo "If empty value, press ENTER"

echo "Input clustername"
read clustername

echo "Input namespace"
read namespace

echo "Input containername"
read containername

DATA='{"clusterName": "'$clustername'", "namespace":"'$namespace'", "containerName":"'$containername'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.observability.Observability.GetSysObservabilityData
