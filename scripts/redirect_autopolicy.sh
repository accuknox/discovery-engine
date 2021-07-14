#!/bin/bash

kubectl port-forward -n accuknox-dev-knoxautopolicy svc/knoxautopolicy --address 0.0.0.0 --address :: 9089:9089
