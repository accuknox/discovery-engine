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
	cd $(CURDIR)/config; go clean -testcache .; go test -v .
	cd $(CURDIR)/feedconsumer; go clean -testcache .; go test -v .
	cd $(CURDIR)/libs; go clean -testcache .; go test -v .
	cd $(CURDIR)/plugin; go clean -testcache .; go test -v .
	cd $(CURDIR)/server; go clean -testcache .; go test -v .
	cd $(CURDIR)/systempolicy; go clean -testcache .; go test -v .

.PHONY: gosec
gosec:
	gosec -exclude=G204,G304,G107 ./...
	
.PHONY: clean
clean:
	cd $(CURDIR); rm -f knoxAutoPolicy go.sum

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
