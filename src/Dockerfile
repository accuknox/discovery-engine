### Builder

FROM golang:1.15.2-buster as builder

WORKDIR /usr/src/knox

COPY ./src/libs ./libs
COPY ./src/logging ./logging
COPY ./src/feedconsumer ./feedconsumer
COPY ./src/config ./config
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

FROM debian:latest

COPY ./src/conf/conf.yaml conf/conf.yaml
COPY --from=builder /usr/src/knox/knoxAutoPolicy /knoxAutoPolicy

ENTRYPOINT ["/knoxAutoPolicy"]
