# STRATUS

AWS Adversary Emulation & Security Testing Framework

**Authorized security testing use only.**

STRATUS is an operator-focused framework for authorized AWS security testing and adversary emulation. It solves the "many compromised identities with different capabilities" problem with centralized identity management, permission intelligence, modular operations, and team collaboration.

## Architecture

- **Core Engine:** Go, single-binary compilation
- **Storage:** SQLite (metadata + append-only audit log) + encrypted vault (AES-256-GCM, Argon2id KDF)
- **CLI:** Cobra-based with full command hierarchy
- **GUI:** Wails v2 + React/TypeScript + D3.js (planned)
- **Teamserver:** gRPC/mTLS with RBAC (planned)

## Building

```bash
make build          # Build CLI binary
make build-server   # Build teamserver binary
make test           # Run tests
make build-all      # Cross-compile for all platforms
```

## Quick Start

```bash
# Create a workspace
stratus workspace new --name "engagement-name" --scope-accounts 123456789012 --scope-regions us-east-1

# Import an IAM key
stratus identity add iam-key --access-key AKIA... --label "ci-readonly"

# Activate a session
stratus sessions use <session-uuid>

# Check session context
stratus sessions whoami
stratus sessions peek

# Explore pivot paths
stratus pivot hops
stratus pivot path --to arn:aws:iam::123456789012:role/Admin

# Export evidence
stratus export --format json --output ./evidence/
```

## Project Structure

```
cmd/
  stratus/           CLI binary entrypoint + Cobra commands
  stratus-server/    Teamserver binary
internal/
  core/              Types, workspace manager, engine
  db/                SQLite schema and database management
  vault/             Encrypted secrets vault (AES-256-GCM + Argon2id)
  identity/          Identity & Session broker
  session/           Session lifecycle and context stack
  graph/             Pivot graph (SQLite adjacency + BFS pathfinding)
  scope/             Blast radius enforcement
  audit/             Append-only audit log with hash chain
  logging/           Structured logging with secret redaction
  aws/               AWS SDK v2 adapter (rate limiting, retry, caching)
  config/            Global and workspace configuration
  grpcapi/           Internal gRPC API skeleton
  module/            Module runtime (planned)
  artifact/          Artifact storage (planned)
pkg/
  sdk/v1/            Module developer SDK interface
proto/               gRPC service definitions
```

## License

Proprietary — Authorized security testing use only.
