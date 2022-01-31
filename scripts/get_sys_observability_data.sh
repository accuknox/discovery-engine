#!/bin/bash

## Run script command in below format
## ./scripts/get_sys_observability_data.sh clustername:default containername:wordpress namespace:wordpress-mysql labels:app=mysql

for ARGUMENT in "$@"
do
    KEY=$(echo $ARGUMENT | cut -f1 -d:)
    VALUE=$(echo $ARGUMENT | cut -f2 -d:)   

    case "$KEY" in
            clustername)        clustername=${VALUE} ;;
            namespace)          namespace=${VALUE} ;;   
            containername)      containername=${VALUE} ;;
            labels)             labels=${VALUE} ;;     
            *)   
    esac    
done

DATA='{"clusterName": "'$clustername'", "namespace":"'$namespace'", "containerName":"'$containername'", "labels":"'$labels'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.observability.Observability.GetSysObservabilityData
