#!/bin/bash

## Run script command in below format"
## ./scripts/convery_sys_policy.sh --clustername default --namespace wordpress-mysql --labels app=mysql

usage() 
{
	cat << EOF
Usage: $0 <options>

Options could be:
--clustername <clustername>
--namespace <namespace>
--labels <set-of-labels> ... for e.g. --labels "xyz=123,abc=456"
--fromsource <binary> ... for e.g. --fromsource "/usr/bin/bash"
EOF
	exit 1
}

OPTS=`getopt -o s: --long clustername: --long namespace: --long labels: --long fromsource: -n 'parse-options' -- "$@"`
eval set -- "$OPTS"
while true; do
    case "$1" in
        --clustername ) CLUSTER_NAME="$2"; shift 2;;
        --namespace ) NAMESPACE="$2"; shift 2;;
        --labels ) LABELS="$2"; shift 2;;
        --fromsource ) FROMSOURCE="$2"; shift 2;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done
##[[ "$REQUEST" == "" ]] && echo "request type [observe|dbclear] not found." && usage

DATA='{"policytype": "system", "clustername": "'$CLUSTER_NAME'", "namespace":"'$NAMESPACE'", "labels":"'$LABELS'", "fromsource":"'$FROMSOURCE'"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.worker.Worker.Convert
