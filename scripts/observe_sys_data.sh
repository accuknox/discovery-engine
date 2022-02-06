#!/bin/bash

## Run script command in below format
## ./scripts/observe_sys_data.sh --clustername default --containername wordpress --namespace wordpress-mysql --labels app=mysql

OPTS=`getopt -o s: --long containername: --long clustername: --long namespace: --long labels: -n 'parse-options' -- "$@"`
eval set -- "$OPTS"
while true; do
    case "$1" in
        --containername ) CONTAINER_NAME="$2"; shift 2;;
        --clustername ) CLUSTER_NAME="$2"; shift 2;;
        --namespace ) NAMESPACE="$2"; shift 2;;
        --labels ) LABELS="$2"; shift 2;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done

DATA='{"clusterName": "'$CLUSTER_NAME'", "namespace":"'$NAMESPACE'", "containerName":"'$CONTAINER_NAME'", "labels":"'$LABELS'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.observability.Observability.GetSysObservabilityData
