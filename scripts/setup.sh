#!/usr/bin/env bash
set -euo pipefail

# Color output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[X]${NC} $1"; exit 1; }

# Ensure we run from repo root
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$0")")"

echo "STRATUS Setup"
echo "============="
echo ""

# 1. Check Go
if command -v go &>/dev/null; then
    GO_VER=$(go version | sed -n 's/.*go\([0-9]*\.[0-9]*\).*/\1/p')
    GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
    if [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 23 ]; }; then
        info "Go $GO_VER"
    else
        fail "Go >= 1.23 required (found $GO_VER). Update: https://go.dev/dl/"
    fi
else
    fail "Go not found. Install: https://go.dev/dl/"
fi

# 2. Check Node.js
if command -v node &>/dev/null; then
    NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VER" -ge 18 ]; then
        info "Node.js $(node --version)"
    else
        fail "Node.js >= 18 required (found v$NODE_VER). Update: https://nodejs.org/"
    fi
else
    fail "Node.js not found. Install: https://nodejs.org/"
fi

# 3. Check/install Wails CLI
if command -v wails &>/dev/null; then
    info "Wails CLI installed"
else
    warn "Wails CLI not found. Installing..."
    go install github.com/wailsapp/wails/v2/cmd/wails@latest
    info "Wails CLI installed"
fi

# 4. Go dependencies
echo ""
echo "Downloading Go modules..."
go mod download
info "Go modules ready"

# 5. Frontend dependencies
echo ""
FRONTEND_DIR="cmd/stratus-gui/frontend"
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo "Installing frontend packages..."
    (cd "$FRONTEND_DIR" && npm install)
fi
info "Frontend packages ready"

# 6. Verify CGO works (sqlite3 needs it)
echo ""
echo "Verifying CGO (sqlite3)..."
if go build ./internal/db/ 2>/dev/null; then
    info "CGO + sqlite3 compiles"
else
    fail "CGO build failed. Ensure a C compiler is installed (Xcode CLT on macOS, gcc on Linux)"
fi

# Done
echo ""
echo "=============================="
echo "Setup complete! Quick start:"
echo ""
echo "  make dev     Start GUI dev mode"
echo "  make build   Build everything"
echo "  make test    Run tests"
echo "  make help    See all targets"
echo "=============================="
