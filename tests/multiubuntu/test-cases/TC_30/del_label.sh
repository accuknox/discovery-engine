#!/bin/bash

kubectl label pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-1-deployment | head -n 1 | awk '{print $1}') -n multiubuntu common-
kubectl label pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-2-deployment | head -n 1 | awk '{print $1}') -n multiubuntu common-
kubectl label pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-3-deployment | head -n 1 | awk '{print $1}') -n multiubuntu common-
kubectl label pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-4-deployment | head -n 1 | awk '{print $1}') -n multiubuntu common-
kubectl label pod $(kubectl -n multiubuntu get pods -o wide | grep  ubuntu-5-deployment | head -n 1 | awk '{print $1}') -n multiubuntu common-
