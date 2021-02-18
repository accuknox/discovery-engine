#!/bin/bash

# remove old images
docker images | grep ubuntu-autopol | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# login docker hub
docker login

if [ $? -ne 0 ]; then
    exit
fi

# create new images
docker build --tag 0x010/ubuntu-autopol:latest .

# push new images
docker push 0x010/ubuntu-autopol:latest
