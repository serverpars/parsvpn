.PHONY: build test coexist tidy

VERSION ?= 1.3.1

build:
	bash scripts/build.sh

test:
	go test ./...

coexist:
	bash tests/coexist/run.sh

tidy:
	go mod tidy
