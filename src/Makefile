CURDIR=$(shell pwd)

ifeq (, $(shell which govvv))
$(shell go install github.com/ahmetb/govvv)	# This works for older go version
$(shell go install github.com/ahmetb/govvv@latest) # This works for new go version
endif

PKG := $(shell go list ./libs)
GIT_INFO := $(shell govvv -flags -pkg $(PKG))

.PHONY: build
build:
	@# for build_image -> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o knoxAutoPolicy main.go
	@# for delve -> cd $(CURDIR); go mod tidy; go build -tags debugger -gcflags="all=-N -l" -o knoxAutoPolicy main.go
	go mod tidy
	go build -ldflags "$(GIT_INFO)" -o knoxAutoPolicy main.go

.PHONY: test
test:
	cd $(CURDIR); go mod tidy
	cd $(CURDIR)/config; go clean -testcache .; go test -v . -coverprofile=../coverage1.out -json > ../report1.json ; go test -cover .
	cd $(CURDIR)/feedconsumer; go clean -testcache .; go test -v . -coverprofile=../coverage2.out -json > ../report2.json ; go test -cover .
	cd $(CURDIR)/libs; go clean -testcache .; go test -v . -coverprofile=../coverage3.out -json > ../report3.json ; go test -cover .
	cd $(CURDIR)/plugin; go clean -testcache .; go test -v . -coverprofile=../coverage4.out -json > ../report4.json ; go test -cover .
	cd $(CURDIR)/server; go clean -testcache .; go test -v . -coverprofile=../coverage5.out -json > ../report5.json ; go test -cover .
	cd $(CURDIR)/systempolicy; go clean -testcache .; go test -v . -coverprofile=../coverage6.out -json > ../report6.json ; go test -cover .
	cat coverage?.out > coverage.out && rm coverage?.out
	cat report?.json > report.json && rm report?.json

.PHONY: gosec
gosec:
	gosec -exclude=G204,G304,G107 ./...
	
.PHONY: clean
clean:
	cd $(CURDIR); rm -f knoxAutoPolicy go.sum

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)

.PHONY: local-release
local-release: build
ifeq (, $(shell which goreleaser))
	@{ \
	set -e ;\
	go install github.com/goreleaser/goreleaser@latest ;\
	}
endif
	cd $(CURDIR); VERSION=$(shell git describe --tags --always --dirty) goreleaser release --rm-dist --skip-publish --skip-sign --skip-validate --snapshot
