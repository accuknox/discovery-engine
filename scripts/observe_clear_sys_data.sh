#!/bin/bash

## Run script command in below format"
## For dbclear, use below format"
## ./scripts/observe_clear_sys_data.sh --req dbclear --clustername default --containername wordpress --namespace wordpress-mysql --labels app=mysql --fromsource apache2 --duration 60(secs)
## For observability, use below format. Currently observability does not support fromsource and duration
## ./scripts/observe_clear_sys_data.sh --req observe --clustername default --containername wordpress --namespace wordpress-mysql --labels app=mysql

usage() 
{
	cat << EOF
Usage: $0 <options>

Options could be:
--req [observe|dbclear]
--clustername <clustername>
--namespace <namespace>
--containername <container-name>
--labels <set-of-labels> ... for e.g. --labels "xyz=123,abc=456"
--fromsource <binary-path>
--duration <1m|1h|1w>
EOF
	exit 1
}

OPTS=`getopt -o s: --long req: --long containername: --long clustername: --long namespace: --long labels: --long fromsource: --long duration: -n 'parse-options' -- "$@"`
eval set -- "$OPTS"
while true; do
    case "$1" in
        --req ) REQUEST="$2"; shift 2;;
        --containername ) CONTAINER_NAME="$2"; shift 2;;
        --clustername ) CLUSTER_NAME="$2"; shift 2;;
        --namespace ) NAMESPACE="$2"; shift 2;;
        --labels ) LABELS="$2"; shift 2;;
        --fromsource ) FROM_SOURCE="$2"; shift 2;;
        --duration ) DURATION="$2"; shift 2;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done
[[ "$REQUEST" == "" ]] && echo "request type [observe|dbclear] not found." && usage

DATA='{"request": "'$REQUEST'", "clusterName": "'$CLUSTER_NAME'", "namespace":"'$NAMESPACE'", "containerName":"'$CONTAINER_NAME'", "labels":"'$LABELS'", "fromSource":"'$FROM_SOURCE'", "duration":"'$DURATION'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.insight.Insight.GetInsightData
