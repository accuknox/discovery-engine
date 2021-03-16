#!/bin/bash

kubectl annotate pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-3-deployment | head -n 1 | awk '{print $1}') -n hipster io.cilium.proxy-visibility="<Egress/53/UDP/DNS>,<Egress/8000/TCP/HTTP>,<Egress/8080/TCP/HTTP>" --overwrite
