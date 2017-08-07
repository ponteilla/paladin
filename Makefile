.PHONY: default deps docker-build

pkg = $(shell go list)

default: deps docker-build

deps:
	@go get -u github.com/FiloSottile/gvt
	@gvt restore

docker-build:
	@docker run --rm -v $(shell pwd):/go/src/$(pkg) -w /go/src/$(pkg) -e "CGO_ENABLED=1" golang:1.8-jessie go build
