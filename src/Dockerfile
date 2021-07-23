### Builder

FROM artifactory.accuknox.com/accuknox/golang:1.15.3-buster as builder

WORKDIR /usr/src/knox

COPY ./src/libs ./libs
COPY ./src/logging ./logging
COPY ./src/feedconsumer ./feedconsumer
COPY ./src/config ./config
COPY ./src/cluster ./cluster
COPY ./src/networkpolicy ./networkpolicy
COPY ./src/systempolicy ./systempolicy
COPY ./src/types ./types
COPY ./src/plugin ./plugin
COPY ./src/protobuf ./protobuf
COPY ./src/server ./server

COPY ./src/main.go ./main.go
COPY ./src/go.mod ./go.mod

RUN go mod download
RUN go build -o knoxAutoPolicy main.go

### Make executable image

#FROM debian:latest
FROM artifactory.accuknox.com/accuknox/ubuntu:21.10

COPY ./src/conf/local.yaml conf/conf.yaml
COPY --from=builder /usr/src/knox/knoxAutoPolicy /knoxAutoPolicy

ENTRYPOINT ["/knoxAutoPolicy"]
