#!/bin/bash

DATA='{"req": "dbclear"}'

grpcurl -plaintext -d "$DATA" localhost:9089 v1.worker.Worker.Start
