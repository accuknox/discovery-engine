### Builder

FROM artifactory.accuknox.com/accuknox/golang:1.15.3-buster as builder

WORKDIR /usr/src/knox

COPY . .

RUN cd src && make

FROM artifactory.accuknox.com/accuknox/ubuntu:22.04

COPY --from=builder /usr/src/knox/src/knoxAutoPolicy /knoxAutoPolicy
COPY --from=builder /usr/src/knox/src/conf/local.yaml /conf/conf.yaml

ENTRYPOINT ["/knoxAutoPolicy"]
