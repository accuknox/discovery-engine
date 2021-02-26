#!/bin/bash

kubectl port-forward -n knox-auto-policy svc/knoxautopolicy --address 0.0.0.0 --address :: 9089:9089
