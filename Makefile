.PHONY: help setup check build build-cli build-server build-gui quick dev test test-coverage clean lint fmt vet build-linux build-darwin build-windows build-all

VERSION ?= 0.1.0-dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
FRONTEND := cmd/stratus-gui/frontend
WAILS_DIR := cmd/stratus-gui

# Default target
help:
	@echo "STRATUS Build System"
	@echo ""
	@echo "Setup:"
	@echo "  make setup        Install all dependencies (Go, Node, Wails, npm packages)"
	@echo "  make check        Verify toolchain is ready"
	@echo ""
	@echo "Development:"
	@echo "  make dev          Start GUI dev mode with hot reload"
	@echo "  make test         Run all Go tests"
	@echo ""
	@echo "Building:"
	@echo "  make build        Build everything (CLI + server + GUI)"
	@echo "  make quick        Build CLI + server only (no frontend, fast)"
	@echo "  make build-cli    Build CLI binary only"
	@echo "  make build-server Build teamserver binary only"
	@echo "  make build-gui    Build GUI binary only"
	@echo ""
	@echo "Other:"
	@echo "  make clean        Remove build artifacts"
	@echo "  make fmt          Format Go code"
	@echo "  make vet          Run Go vet"
	@echo "  make lint         Run golangci-lint"

setup:
	@bash scripts/setup.sh

check:
	@echo "Checking toolchain..."
	@command -v go >/dev/null 2>&1 || { echo "MISSING: Go (install from https://go.dev/dl/)"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "MISSING: Node.js (install from https://nodejs.org/)"; exit 1; }
	@command -v wails >/dev/null 2>&1 || { echo "MISSING: Wails CLI (run: go install github.com/wailsapp/wails/v2/cmd/wails@latest)"; exit 1; }
	@echo "Go:    $$(go version)"
	@echo "Node:  $$(node --version)"
	@echo "Wails: $$(wails version 2>/dev/null | head -1)"
	@echo "All tools ready."

build: build-cli build-server build-gui

quick: build-cli build-server

build-cli:
	@echo "Building CLI..."
	@go build $(LDFLAGS) -o bin/stratus ./cmd/stratus
	@echo "  -> bin/stratus"

build-server:
	@echo "Building teamserver..."
	@go build $(LDFLAGS) -o bin/stratus-server ./cmd/stratus-server
	@echo "  -> bin/stratus-server"

build-gui: $(FRONTEND)/node_modules
	@echo "Building GUI..."
	@cd $(WAILS_DIR) && wails build
	@echo "  -> $(WAILS_DIR)/build/bin/"

# Auto-install npm deps if node_modules missing
$(FRONTEND)/node_modules: $(FRONTEND)/package.json
	@echo "Installing frontend dependencies..."
	@cd $(FRONTEND) && npm install
	@touch $@

dev: $(FRONTEND)/node_modules
	@cd $(WAILS_DIR) && wails dev

test:
	go test -v -race -count=1 ./...

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/ dist/ $(WAILS_DIR)/build/

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

# Cross-compilation (CLI + server only, no GUI)
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-linux-amd64 ./cmd/stratus
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/stratus-linux-arm64 ./cmd/stratus

build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-darwin-amd64 ./cmd/stratus
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/stratus-darwin-arm64 ./cmd/stratus

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/stratus-windows-amd64.exe ./cmd/stratus

build-all: build-linux build-darwin build-windows
