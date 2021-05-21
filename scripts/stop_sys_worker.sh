#!/bin/bash

DATA='{"policytype": "system"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.worker.Worker.Stop
