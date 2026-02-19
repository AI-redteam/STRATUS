#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Quick dep check
command -v go &>/dev/null || { echo "Go not found. Run 'make setup' first."; exit 1; }
command -v node &>/dev/null || { echo "Node.js not found. Run 'make setup' first."; exit 1; }
command -v wails &>/dev/null || { echo "Wails CLI not found. Run 'make setup' first."; exit 1; }

MODE="${1:-gui}"

case "$MODE" in
    --cli)
        echo "Building CLI..."
        go build -o bin/stratus ./cmd/stratus
        echo "Done: bin/stratus"
        ;;
    --server)
        echo "Building teamserver..."
        go build -o bin/stratus-server ./cmd/stratus-server
        echo "Done: bin/stratus-server"
        ;;
    gui|*)
        # Auto npm install if needed
        FRONTEND="cmd/stratus-gui/frontend"
        [ -d "$FRONTEND/node_modules" ] || (echo "Installing frontend deps..." && cd "$FRONTEND" && npm install)
        cd cmd/stratus-gui && exec wails dev
        ;;
esac
