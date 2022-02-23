#!/bin/bash

DATA='{"policytype": "network"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.worker.Worker.Convert
