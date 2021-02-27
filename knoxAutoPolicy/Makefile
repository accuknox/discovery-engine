CURDIR=$(shell pwd)

.PHONY: build
build:
	# for build_image -> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o knoxAutoPolicy main.go
	cd $(CURDIR); go build -o knoxAutoPolicy main.go

.PHONY: test
test:
	cd $(CURDIR)/core; go clean -testcache .; go test -v .
	cd $(CURDIR)/libs; go clean -testcache .; go test -v .
	cd $(CURDIR)/plugin; go clean -testcache .; go test -v .
	cd $(CURDIR)/server; go clean -testcache .; go test -v .

.PHONY: clean
clean:
	cd $(CURDIR); rm -f knoxAutoPolicy go.sum

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
