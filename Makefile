.PHONY: build test check linux clean

VERSION ?= dev

build:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/firefighter ./cmd/firefighter
	go build -trimpath -ldflags "-s -w" -o bin/firefighter-grokbot ./plugins/grokbot/cmd

test:
	go test -race ./...

check: test
	go vet ./...

linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/firefighter-linux-amd64 ./cmd/firefighter
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/firefighter-linux-arm64 ./cmd/firefighter
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/firefighter-grokbot-linux-amd64 ./plugins/grokbot/cmd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/firefighter-grokbot-linux-arm64 ./plugins/grokbot/cmd

clean:
	rm -rf bin dist
