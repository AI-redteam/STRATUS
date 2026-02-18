# STRATUS

AWS Adversary Emulation & Security Testing Framework

**Authorized security testing use only.**

STRATUS is an operator-focused framework for authorized AWS security testing and adversary emulation. It solves the "many compromised identities with different capabilities" problem with centralized identity management, permission intelligence, modular operations, and team collaboration.

## Architecture

- **Core Engine:** Go, single-binary compilation
- **Storage:** SQLite (metadata + append-only audit log) + encrypted vault (AES-256-GCM, Argon2id KDF)
- **CLI:** Cobra-based with full command hierarchy
- **Teamserver:** gRPC with JSON-RPC dispatch for multi-operator collaboration
- **GUI:** Wails v2 + React/TypeScript + D3.js

## Building

```bash
make build          # Build CLI binary
make build-server   # Build teamserver binary
make build-gui      # Build GUI (Wails + React)
make dev-gui        # GUI dev mode with hot reload
make test           # Run tests
make build-all      # Cross-compile for all platforms
```

## Quick Start

```bash
# Create a workspace
stratus workspace new --name "engagement-name" --scope-accounts 123456789012 --scope-regions us-east-1

# Import an IAM key
stratus identity add iam-key --access-key AKIA... --label "ci-readonly"

# Import IMDS-captured credentials
stratus identity add imds-capture --json-file ./imds-creds.json --region us-east-1

# Activate a session
stratus sessions use <session-uuid>

# Check session context (with live STS verification)
stratus sessions whoami
stratus sessions peek

# Run a module
stratus run com.stratus.iam.enumerate-roles
stratus run com.stratus.iam.enumerate-roles --dry-run
stratus run com.stratus.s3.find-public-buckets --inputs '{"check_acl":true}'

# Explore pivot paths
stratus pivot hops
stratus pivot path --to arn:aws:iam::123456789012:role/Admin
stratus pivot assume arn:aws:iam::123456789012:role/LateralTarget

# Manage artifacts
stratus artifacts list
stratus artifacts create evidence.json --label "API response" --type json_result
stratus artifacts get <uuid> --output evidence-copy.json
stratus artifacts verify

# Check scope compliance
stratus scope show
stratus scope check --region eu-west-1 --account 123456789012

# Export evidence
stratus export --format json --output ./evidence/
stratus export --format markdown --output ./report/
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `workspace new/list/activate` | Workspace lifecycle management |
| `identity add <type>/list/info/archive` | Identity import (IAM key, STS, IMDS, assume role, web identity, cred process) |
| `sessions list/use/push/pop/peek/whoami/health/refresh/expire` | Session management with LIFO context stack |
| `pivot assume/graph/hops/path/stats` | Lateral movement and pivot graph |
| `run <module-id>` | Execute modules with --dry-run and --preflight |
| `modules search/list/info` | Browse available modules |
| `runs list/show` | View module execution history |
| `scope show/update/check` | Blast radius scope management |
| `artifacts list/show/create/get/verify` | Content-addressed artifact storage |
| `note add/list/show/update/delete` | Engagement note management |
| `export --format json/markdown` | Evidence export |
| `aws <service> <operation>` | Convenience AWS API wrappers (sts, iam, s3, ec2, lambda, etc.) |
| `awsraw` | Direct AWS API access escape hatch |

## Built-in Modules

| ID | Name | Risk | Services |
|----|------|------|----------|
| `com.stratus.iam.enumerate-roles` | Enumerate IAM Roles | read_only | IAM |
| `com.stratus.iam.enumerate-users` | Enumerate IAM Users | read_only | IAM |
| `com.stratus.s3.find-public-buckets` | Find Public S3 Buckets | read_only | S3 |
| `com.stratus.cloudtrail.status` | CloudTrail Configuration Audit | read_only | CloudTrail |
| `com.stratus.kms.key-inventory` | KMS Key Inventory | read_only | KMS |
| `com.stratus.lambda.enumerate-functions` | Enumerate Lambda Functions | read_only | Lambda |
| `com.stratus.ec2.enumerate-instances` | Enumerate EC2 Instances | read_only | EC2 |
| `com.stratus.ec2.security-group-audit` | Security Group Audit | read_only | EC2 |
| `com.stratus.iam.create-access-key` | Create IAM Access Key | write | IAM |
| `com.stratus.cloudtrail.stop-trail` | Stop CloudTrail Logging | destructive | CloudTrail |
| `com.stratus.ec2.modify-security-group` | Modify Security Group | write | EC2 |

## Teamserver

```bash
# Initialize PKI (first time only)
stratus-server init-pki --pki-dir /path/to/pki --hosts teamserver.internal,10.0.0.5

# Generate operator certificates
stratus-server gen-client --pki-dir /path/to/pki --name operator-alice
stratus-server gen-client --pki-dir /path/to/pki --name operator-bob

# Start teamserver with mTLS
stratus-server serve --workspace /path/to/workspace --passphrase "$VAULT_PASS" --pki-dir /path/to/pki

# Start without mTLS (dev/local only)
stratus-server serve --workspace /path/to/workspace --passphrase "$VAULT_PASS" --insecure
```

The teamserver exposes the full STRATUS API over gRPC with mutual TLS (mTLS) authentication. Each operator connects with a client certificate signed by the engagement CA. Supports workspace, identity, session, graph, module, and audit operations for multi-operator collaboration.

## GUI

The STRATUS GUI provides a full read-only operator console with six views:

- **Dashboard** — Workspace overview, stat cards, scope display, recent runs, audit health
- **Identities** — Browse imported identities, filter/sort, archive, linked session detail
- **Sessions** — Session list with LIFO context stack visualization, activate/push/pop/expire
- **Modules** — Card grid with search/filter, module detail, run dialog with auto-generated inputs
- **Graph** — D3.js force-directed pivot graph with zoom/pan/drag, path finder, node coloring
- **Audit** — Append-only audit log with chain verification, event filtering, paginated detail

```bash
# Prerequisites: Go 1.23+, Node.js 18+, Wails v2
# Install Wails: go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Development mode (hot reload)
make dev-gui

# Production build
make build-gui
```

## Project Structure

```
cmd/
  stratus/           CLI binary entrypoint + Cobra commands
  stratus-server/    Teamserver binary
  stratus-gui/       GUI binary (Wails v2 + React/TypeScript)
internal/
  core/              Types, workspace manager, engine
  db/                SQLite schema and database management
  vault/             Encrypted secrets vault (AES-256-GCM + Argon2id)
  identity/          Identity & Session broker (7 import methods)
  session/           Session lifecycle and LIFO context stack
  graph/             Pivot graph (SQLite adjacency + BFS pathfinding)
  scope/             Blast radius enforcement (region, account, partition, ARN)
  audit/             Append-only audit log with SHA-256 hash chain
  artifact/          Content-addressed artifact storage with integrity verification
  module/            Module registry, runner, and 11 built-in modules
  pki/               mTLS certificate authority and certificate generation
  logging/           Structured logging with secret redaction
  aws/               AWS SDK v2 adapter (rate limiting, retry, caching, audit)
  config/            Global and workspace configuration
  grpcapi/           gRPC API service layer and JSON-RPC handler
pkg/
  sdk/v1/            Module developer SDK interface
proto/               gRPC service definitions
```

## Security Model

- **Vault:** AES-256-GCM encryption with Argon2id key derivation
- **mTLS:** ECDSA P-256 certificates, TLS 1.3 minimum, mutual authentication for teamserver
- **Audit:** Append-only hash chain for tamper detection
- **Scope:** Multi-layer enforcement (module runner, AWS adapter, CLI commands, pivot operations)
- **Artifacts:** SHA-256 content hashing with integrity verification

## License

Proprietary — Authorized security testing use only.
