.PHONY: build test coexist tidy

build:
	bash scripts/build.sh

test:
	go test ./...

coexist:
	bash tests/coexist/run.sh

tidy:
	go mod tidy
