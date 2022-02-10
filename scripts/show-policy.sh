#!/bin/bash

# example: ./show-policy.sh -n explorer -c mysql
# example: ./show-policy.sh -c kabuntu

BASE=`dirname $0`
SRC="$BASE/../src"

usage()
{
	echo "Usage: $0 -n|--namespace <namespace> -c|--container <containername> ... containername is mandatory"
	exit 1
}

function age() {
   local changed=`stat -c %Y "$1"`
   local now=`date +%s`
   local elapsed

   let elapsed=now-changed
   echo $elapsed
}

parse_args()
{
	NS="default"
	OPTS=`getopt -o c:n: --long container:namespace: -n 'parse-options' -- "$@"`
    eval set -- "$OPTS"
    while true; do
        case "$1" in
            -n | --namespace ) NS="$2"; shift 2;;
            -c | --container ) CONTNAME="$2"; shift 2;;
            -- ) shift; break ;;
            * ) break ;;
        esac
    done
    [[ "$CONTNAME" == "" ]] && echo "No containername provided." && usage
}

main()
{
	rm -rf $SRC/kubearmor_policies_*.yaml 2>/dev/null
	$BASE/convert_sys_policy.sh 2>&1 >/dev/null || exit 1
	newf=`ls -1 $SRC/kubearmor_policies_default_${NS}_${CONTNAME}_*.yaml` || exit 1

	prevf="/tmp/previous.yaml"
	if [ -f $prevf ]; then
		[[ $(age $prevf) -gt 10 ]] && cp $newf $prevf #override prevf if older than 10sec
		diff -q $prevf $newf > /dev/null
		if [ $? -ne 0 ]; then
			diff -y $prevf $newf | grep "^ *process" -A 1000 | colordiff
		else
			grep "^ *process" -A 1000 $newf
		fi
	fi
	cp $newf $prevf
}

parse_args $*
main
