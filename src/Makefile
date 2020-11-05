CURDIR=$(shell pwd)

.PHONY: build
build:
	# for build_image (manager) -> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o bastion_manager main.go
	go build -o knoxAutoPolicy main.go

.PHONY: clean
clean:
	rm -f knoxAutoPolicy go.sum

.PHONY: image
image:
	cd $(CURDIR)/../build; $(MAKE)
