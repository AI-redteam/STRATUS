# STRATUS

**AWS Adversary Emulation & Security Testing Framework**

> Authorized security testing use only.

STRATUS is an operator-focused framework for authorized AWS security testing and adversary emulation. Think Metasploit/Cobalt Strike mental model applied to the AWS cloud: centralized identity management, permission-aware pivot graphing, modular offensive operations, and full audit trail for evidence collection.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Quick Start (CLI)](#quick-start-cli)
- [GUI](#gui)
- [CLI Reference](#cli-reference)
- [Built-in Modules](#built-in-modules)
- [Teamserver](#teamserver)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Features

- **Multi-identity management** — Import and switch between IAM keys, STS sessions, IMDS-captured creds, assumed roles, web identity tokens, and credential processes
- **LIFO session stack** — Push/pop session contexts like a debugger call stack, with health monitoring and automatic refresh
- **Pivot graph** — SQLite-backed directed graph with BFS pathfinding; trust policy parsing auto-discovers `can_assume` edges between principals and roles
- **11 built-in modules** — Recon (IAM, S3, EC2, Lambda, KMS, CloudTrail), write (create access keys, modify security groups), and destructive (stop CloudTrail) operations
- **Blast radius scope enforcement** — 4-layer enforcement (module runner, AWS adapter, CLI commands, pivot operations) for region, account, partition, and ARN boundaries
- **Encrypted vault** — AES-256-GCM with Argon2id KDF protects all credential material at rest
- **Append-only audit log** — SHA-256 hash chain records every API call, module run, and identity operation for tamper-evident evidence
- **Content-addressed artifacts** — SHA-256 hashed file store with integrity verification for engagement evidence
- **GUI operator console** — Wails v2 desktop app with D3.js force-directed graph, module browser, identity/session management, and audit viewer
- **Teamserver** — gRPC with mTLS (ECDSA P-256, TLS 1.3) for multi-operator collaboration
- **Export** — JSON and Markdown evidence export for reporting

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Operator Interfaces                │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   CLI    │  │  GUI (Wails) │  │   Teamserver   │  │
│  │  Cobra   │  │  React + D3  │  │  gRPC + mTLS   │  │
│  └────┬─────┘  └──────┬───────┘  └───────┬────────┘  │
│       │               │                  │            │
│       └───────────────┼──────────────────┘            │
│                       ▼                               │
│              ┌─────────────────┐                      │
│              │  grpcapi.Service │  Transport-agnostic  │
│              │  (business logic)│  API layer           │
│              └────────┬────────┘                      │
│                       ▼                               │
│              ┌─────────────────┐                      │
│              │   core.Engine   │  Wires all subsystems │
│              └────────┬────────┘                      │
│       ┌───────┬───────┼───────┬───────┬───────┐      │
│       ▼       ▼       ▼       ▼       ▼       ▼      │
│  ┌────────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌────┐  │
│  │Identity│ │Sess.│ │Graph│ │Modul│ │Audit│ │Vault│  │
│  │ Broker │ │Stack│ │Store│ │Runnr│ │ Log │ │     │  │
│  └────────┘ └─────┘ └─────┘ └─────┘ └─────┘ └────┘  │
│       │       │       │       │       │       │      │
│       └───────┴───────┼───────┴───────┘       │      │
│                       ▼                       ▼      │
│              ┌─────────────────┐     ┌─────────────┐  │
│              │    SQLite DBs   │     │  Encrypted   │  │
│              │ metadata + audit│     │  Vault File  │  │
│              └─────────────────┘     └─────────────┘  │
│                       │                               │
│                       ▼                               │
│              ┌─────────────────┐                      │
│              │  AWS SDK v2     │  Rate limited,        │
│              │  Adapter Layer  │  cached, audit-logged │
│              └─────────────────┘                      │
└──────────────────────────────────────────────────────┘
```

- **Core Engine** (`core.Engine`) — Wires MetadataDB, AuditDB, Vault, AuditLogger, and Workspace
- **Service Layer** (`grpcapi.Service`) — 30+ methods shared by CLI, GUI, and teamserver
- **Storage** — SQLite for metadata + audit, AES-256-GCM encrypted vault for secrets
- **AWS Adapter** — SDK v2 with per-service rate limiting, TTL response caching, and audit logging

## Prerequisites

| Dependency | Version | Notes |
|------------|---------|-------|
| Go | 1.23+ | toolchain 1.24.7; CGO required (sqlite3) |
| Node.js | 18+ | For GUI frontend build |
| Wails | v2 | `go install github.com/wailsapp/wails/v2/cmd/wails@latest` |

## Building

```bash
# CLI binary
make build                  # → bin/stratus

# Teamserver binary
make build-server           # → bin/stratus-server

# GUI (desktop app)
cd cmd/stratus-gui/frontend && npm install   # first time only
make build-gui              # → cmd/stratus-gui/build/bin/

# All targets
make build build-server build-gui

# Run tests (15 packages)
make test

# Cross-compile CLI for Linux/macOS/Windows
make build-all
```

## Quick Start (CLI)

```bash
# 1. Create a workspace (sets up encrypted vault, databases, scope)
stratus workspace new \
  --name "engagement-name" \
  --scope-accounts 123456789012 \
  --scope-regions us-east-1

# 2. Import credentials
stratus identity add iam-key --access-key AKIA... --label "ci-readonly"
stratus identity add sts-session --access-key ASIA... --session-token "..." --label "lambda-creds"
stratus identity add imds-capture --json-file ./imds-creds.json --region us-east-1

# 3. Activate a session
stratus sessions list
stratus sessions use <session-uuid>
stratus sessions whoami          # Live STS verification

# 4. Run reconnaissance
stratus run com.stratus.iam.enumerate-roles
stratus run com.stratus.iam.enumerate-users --inputs '{"max_users":100}'
stratus run com.stratus.s3.find-public-buckets --dry-run

# 5. Explore the pivot graph
stratus pivot hops               # Show reachable nodes from current identity
stratus pivot path --to arn:aws:iam::123456789012:role/Admin
stratus pivot assume arn:aws:iam::123456789012:role/LateralTarget

# 6. Manage context stack (push before pivoting, pop to return)
stratus sessions push <session-uuid>
stratus sessions peek
stratus sessions pop

# 7. Collect evidence
stratus artifacts list
stratus artifacts create evidence.json --label "API response" --type json_result
stratus artifacts verify          # SHA-256 integrity check

# 8. Export
stratus export --format json --output ./evidence/
stratus export --format markdown --output ./report/
```

## GUI

The STRATUS GUI is a native desktop application (Wails v2) providing a full operator console.

### Running

```bash
# Development mode (hot reload for frontend changes)
make dev-gui

# Production build
make build-gui
```

### Views

| View | Description |
|------|-------------|
| **Dashboard** | Workspace overview, 4 stat cards (identities, sessions, graph nodes, module runs), scope display, recent runs table, audit chain health |
| **Identities** | Filterable identity table, detail panel with linked sessions, import dialog (IAM Key / STS Session), archive action |
| **Sessions** | Session list with health badges, LIFO stack visualization from `PeekStack()`, activate/push/pop/expire actions |
| **Modules** | Card grid with search + service + risk class filters, module detail panel (inputs, required IAM actions, references), run dialog with auto-generated input forms, dry-run toggle, destructive operation warnings |
| **Graph** | D3.js force-directed pivot graph with zoom/pan/drag, node coloring by type (IAM user, role, service, account root), edge styling by relationship, path finder with source/target selectors, node detail sidebar with outgoing edges |
| **Audit** | Audit chain verification banner, event type filter, paginated event table (50/page), expandable JSON detail per event |

### GUI Architecture

The GUI is a thin Wails wrapper around the same `grpcapi.Service` layer that backs the CLI and teamserver. The `App` struct in `cmd/stratus-gui/app.go` delegates all operations to the service — no business logic duplication. Wails auto-generates TypeScript bindings from the exported Go methods.

```
cmd/stratus-gui/
  main.go              Wails entrypoint (embeds frontend/dist)
  app.go               App struct: ~35 bound methods → grpcapi.Service
  wails.json           Wails v2 configuration
  frontend/
    src/
      App.tsx           Root component, workspace state, routing
      views/            6 views (Dashboard, Identities, Sessions, Modules, Graph, Audit)
      components/       Shared UI (Badge, DataTable, DetailPanel, Sidebar, Header, Spinner)
      hooks/            Typed Wails binding wrappers
      lib/              Utilities (formatters, D3 graph engine, color maps)
      types/            TypeScript interfaces mirroring Go types
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `workspace new/list/activate` | Workspace lifecycle management |
| `identity add <type>/list/info/archive` | Import credentials (IAM key, STS, IMDS, assume role, web identity, cred process) |
| `sessions list/use/push/pop/peek/whoami/health/refresh/expire` | Session management with LIFO context stack |
| `pivot assume/graph/hops/path/stats` | Lateral movement and pivot graph |
| `run <module-id>` | Execute modules with `--dry-run` and `--preflight` |
| `modules search/list/info` | Browse available modules |
| `runs list/show` | View module execution history |
| `scope show/update/check` | Blast radius scope management |
| `artifacts list/show/create/get/verify` | Content-addressed artifact storage |
| `note add/list/show/update/delete` | Engagement note management |
| `export --format json/markdown` | Evidence export |
| `aws <service> <operation>` | Convenience AWS API wrappers (sts, iam, s3, ec2, lambda, cloudtrail, kms, logs, ssm, secretsmanager) |
| `awsraw` | Direct AWS API access escape hatch |

## Built-in Modules

### Reconnaissance (read_only)

| ID | Name | Services | Description |
|----|------|----------|-------------|
| `com.stratus.iam.enumerate-roles` | Enumerate IAM Roles | IAM | Lists roles, parses trust policies, populates pivot graph with `can_assume` edges |
| `com.stratus.iam.enumerate-users` | Enumerate IAM Users | IAM | Lists users with group memberships, policies, access keys, MFA status |
| `com.stratus.s3.find-public-buckets` | Find Public S3 Buckets | S3 | Scans buckets for public access (ACL + policy analysis) |
| `com.stratus.cloudtrail.status` | CloudTrail Config Audit | CloudTrail | Audits trail configuration, multi-region settings, logging status |
| `com.stratus.kms.key-inventory` | KMS Key Inventory | KMS | Inventories KMS keys with rotation status and key policies |
| `com.stratus.lambda.enumerate-functions` | Enumerate Lambda Functions | Lambda | Lists functions with runtime, memory, VPC config |
| `com.stratus.ec2.enumerate-instances` | Enumerate EC2 Instances | EC2 | Lists instances across regions with security group mappings |
| `com.stratus.ec2.security-group-audit` | Security Group Audit | EC2 | Identifies security groups with overly permissive ingress rules |

### Offensive (write / destructive)

| ID | Name | Risk | Description |
|----|------|------|-------------|
| `com.stratus.iam.create-access-key` | Create IAM Access Key | write | Creates a new access key for a target IAM user |
| `com.stratus.ec2.modify-security-group` | Modify Security Group | write | Adds ingress rules to a security group |
| `com.stratus.cloudtrail.stop-trail` | Stop CloudTrail Logging | destructive | Stops a CloudTrail trail (defense evasion) |

All write/destructive modules include mandatory dry-run logging, scope enforcement, and audit chain recording.

## Teamserver

```bash
# Initialize PKI (first time only)
stratus-server init-pki --pki-dir /path/to/pki --hosts teamserver.internal,10.0.0.5

# Generate operator certificates
stratus-server gen-client --pki-dir /path/to/pki --name operator-alice
stratus-server gen-client --pki-dir /path/to/pki --name operator-bob

# Start with mTLS
stratus-server serve \
  --workspace /path/to/workspace \
  --passphrase "$VAULT_PASS" \
  --pki-dir /path/to/pki

# Start without mTLS (dev/local only)
stratus-server serve --workspace /path/to/workspace --passphrase "$VAULT_PASS" --insecure
```

The teamserver exposes the full STRATUS API over gRPC using a JSON-RPC dispatch pattern. Each operator authenticates with an ECDSA P-256 client certificate signed by the engagement CA. All 30+ operations (workspace, identity, session, graph, module, audit, notes, scope) are available remotely.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Secrets at rest** | AES-256-GCM encryption, Argon2id key derivation (vault passphrase) |
| **Transport** | mTLS with ECDSA P-256 certificates, TLS 1.3 minimum |
| **Audit integrity** | Append-only SHA-256 hash chain (tamper detection) |
| **Blast radius** | 4-layer scope enforcement: module runner → AWS adapter → CLI commands → pivot operations |
| **Artifact integrity** | SHA-256 content-addressed storage with verification |
| **Secret redaction** | Structured logging with automatic credential masking |

## Project Structure

```
cmd/
  stratus/                CLI binary (Cobra) — 12 command files
  stratus-server/         Teamserver binary (gRPC + mTLS)
  stratus-gui/            GUI binary (Wails v2 + React/TypeScript + D3.js)
internal/
  core/                   6 primitives: Workspace, Identity, Session, Scope, Module, Artifact
  db/                     SQLite schema (12 tables) and database management
  vault/                  Encrypted secrets vault (AES-256-GCM + Argon2id)
  identity/               Credential import broker (7 import methods)
  session/                Session lifecycle and LIFO context stack with refresh
  graph/                  SQLite-backed pivot graph with BFS pathfinding + trust policy parser
  scope/                  Blast radius enforcement (region, account, partition, ARN)
  audit/                  Append-only hash chain audit log
  artifact/               Content-addressed file store (SHA-256 hashing, integrity verification)
  module/                 Module registry, runner, and 11 built-in modules
  pki/                    mTLS certificate authority and certificate generation
  logging/                Structured logging with secret redaction
  aws/                    AWS SDK v2 adapter (rate limiting, retry, caching, audit logging)
  config/                 Global and workspace configuration
  grpcapi/                Transport-agnostic API service layer + JSON-RPC handler
pkg/
  sdk/v1/                 Module developer SDK interface
```

**Codebase stats:** ~19,300 lines Go across 68 files, ~2,000 lines TypeScript across 20 frontend files, 15 test packages passing.

## Development

```bash
# Run all tests with race detection
make test

# Run tests with coverage
make test-coverage

# Format and vet
make fmt
make vet

# Lint (requires golangci-lint)
make lint

# GUI development with hot reload
make dev-gui
```

### Key development patterns

- **Engine pattern** — `core.Engine` wires all subsystems; CLI uses `loadActiveEngine()`, GUI uses `core.OpenWorkspace()`
- **Service layer** — `grpcapi.Service` contains all business logic; CLI/GUI/teamserver are thin wrappers
- **Sessions are immutable** — Refresh creates a new `SessionRecord` with `ChainParentSessionUUID`
- **Vault persistence** — Must call `vault.Save()` after `vault.Put()` to persist to disk
- **ClientFactory credentials** — Call `SetDefaultCredentials()` before module execution; modules create region-only creds and the factory merges the secret material
- **Trust policies** — AWS API returns URL-encoded trust policy documents; must `url.QueryUnescape` before parsing

## License

Proprietary — Authorized security testing use only.
