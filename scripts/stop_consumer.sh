#!/bin/bash

grpcurl -plaintext localhost:9089 v1.consumer.Consumer.Stop
