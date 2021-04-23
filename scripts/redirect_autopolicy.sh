#!/bin/bash

kubectl port-forward -n accuknox-autopolicy svc/knoxautopolicy --address 0.0.0.0 --address :: 9089:9089
