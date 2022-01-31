#!/bin/bash

echo "Input requested parameters for fetching observability data."
echo "If empty value, press ENTER"

echo "Input clustername"
read clustername

echo "Input containername"
read containername

echo "Input namespace"
read namespace

echo "Input labels"
read labels

DATA='{"clusterName": "'$clustername'", "namespace":"'$namespace'", "containerName":"'$containername'", "labels":"'$labels'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.observability.Observability.GetSysObservabilityData
