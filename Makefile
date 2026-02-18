.PHONY: all build build-server build-gui dev-gui clean test lint fmt vet

VERSION ?= 0.1.0-dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

all: build build-server

build:
	go build $(LDFLAGS) -o bin/stratus ./cmd/stratus

build-server:
	go build $(LDFLAGS) -o bin/stratus-server ./cmd/stratus-server

build-gui:
	cd cmd/stratus-gui && wails build

dev-gui:
	cd cmd/stratus-gui && wails dev

clean:
	rm -rf bin/ dist/ cmd/stratus-gui/build/

test:
	go test -v -race -count=1 ./...

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

# Cross-compilation targets
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-linux-amd64 ./cmd/stratus
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/stratus-linux-arm64 ./cmd/stratus

build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-darwin-amd64 ./cmd/stratus
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/stratus-darwin-arm64 ./cmd/stratus

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-windows-amd64.exe ./cmd/stratus

build-all: build-linux build-darwin build-windows
