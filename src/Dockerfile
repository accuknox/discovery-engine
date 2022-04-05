### Builder

FROM artifactory.accuknox.com/accuknox/golang:1.18.0-bullseye as builder

WORKDIR /usr/src/knox

COPY . .

RUN curl -O -L https://github.com/fullstorydev/grpcurl/releases/download/v1.8.5/grpcurl_1.8.5_linux_x86_64.tar.gz
RUN tar xf grpcurl_1.8.5_linux_x86_64.tar.gz

RUN cd src && make

FROM artifactory.accuknox.com/accuknox/ubuntu:22.04

COPY --from=builder /usr/src/knox/grpcurl /usr/local/bin/grpcurl
COPY --from=builder /usr/src/knox/scripts/convert_net_policy.sh /convert_net_policy.sh
COPY --from=builder /usr/src/knox/scripts/dbclear.sh /dbclear.sh
COPY --from=builder /usr/src/knox/scripts/convert_sys_policy.sh /convert_sys_policy.sh
COPY --from=builder /usr/src/knox/scripts/observe_clear_sys_data.sh /observe_clear_sys_data.sh
COPY --from=builder /usr/src/knox/src/knoxAutoPolicy /knoxAutoPolicy
COPY --from=builder /usr/src/knox/src/conf/local.yaml /conf/conf.yaml

ENTRYPOINT ["/knoxAutoPolicy"]
