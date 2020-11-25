#!/bin/bash

find ./cilium_policies_*.yaml | xargs -I {} kubectl delete -f {}
