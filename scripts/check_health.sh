#!/bin/bash

grpcurl -plaintext localhost:9089 grpc.health.v1.Health/Check
