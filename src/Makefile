CURDIR=$(shell pwd)

.PHONY: build
build:
	# for build_image -> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o knoxAutoPolicy main.go
	go build -o knoxAutoPolicy main.go

.PHONY: protoinstall
protoinstall:
	go install google.golang.org/protobuf/cmd/protoc-gen-go

.PHONY: pb
pb:
	protoc -I=. --go_out . --go_opt paths=source_relative --go-grpc_out . --go-grpc_opt paths=source_relative protos/v1/config/config.proto
	protoc -I=. --go_out . --go_opt paths=source_relative --go-grpc_out . --go-grpc_opt paths=source_relative protos/v1/worker/worker.proto

.PHONY: clean
clean:
	rm -f knoxAutoPolicy go.sum

.PHONY: image
image:
	cd $(CURDIR)/../build; $(MAKE)
