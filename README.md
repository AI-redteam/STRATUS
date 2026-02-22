# STRATUS

**AWS Adversary Emulation & Security Testing Framework**

> Authorized security testing use only.

STRATUS is an operator-focused framework for authorized AWS security testing and adversary emulation. Think Metasploit/Cobalt Strike mental model applied to the AWS cloud: centralized identity management, permission-aware pivot graphing, modular offensive operations, attack path analysis, and full audit trail for evidence collection.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Building](#building)
- [Quick Start (CLI)](#quick-start-cli)
- [GUI](#gui)
- [CLI Reference](#cli-reference)
- [Built-in Modules](#built-in-modules)
- [Attack Path Analysis](#attack-path-analysis)
- [Teamserver](#teamserver)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Features

- **Multi-identity management** -- Import and switch between IAM keys, STS sessions, IMDS-captured creds, assumed roles, web identity tokens, and credential processes
- **LIFO session stack** -- Push/pop session contexts like a debugger call stack, with health monitoring and automatic refresh
- **Pivot graph** -- SQLite-backed directed graph with BFS pathfinding; trust policy parsing auto-discovers `can_assume` edges between principals and roles
- **36 built-in modules** -- Reconnaissance, privilege escalation analysis, and attack path discovery across 16 AWS services (IAM, STS, S3, EC2, EBS, Lambda, KMS, CloudTrail, CloudWatch, RDS, DynamoDB, ECS, EKS, SNS, Secrets Manager, SSM, MWAA, SageMaker, AWS Config, CodeBuild, Cognito), plus write and destructive operations
- **Attack path analysis** -- Correlates pivot graph edges with privilege escalation findings to identify and rank exploitable chains from the current identity to high-value targets
- **Blast radius scope enforcement** -- 4-layer enforcement (module runner, AWS adapter, CLI commands, pivot operations) for region, account, partition, and ARN boundaries
- **Encrypted vault** -- AES-256-GCM with Argon2id KDF protects all credential material at rest
- **Append-only audit log** -- SHA-256 hash chain records every API call, module run, and identity operation for tamper-evident evidence
- **Content-addressed artifacts** -- SHA-256 hashed file store with integrity verification for engagement evidence
- **GUI operator console** -- Wails v2 desktop app with 12 views, D3.js force-directed graph, attack path visualization, module browser, identity/session management, and audit viewer
- **Teamserver** -- gRPC with mTLS (ECDSA P-256, TLS 1.3) for multi-operator collaboration
- **Export** -- JSON and Markdown evidence export for reporting

## Architecture

```
+---------------------------------------------------------+
|                    Operator Interfaces                   |
|  +----------+  +--------------+  +------------------+   |
|  |   CLI    |  |  GUI (Wails) |  |    Teamserver    |   |
|  |  Cobra   |  |  React + D3  |  |   gRPC + mTLS    |   |
|  +----+-----+  +------+-------+  +--------+---------+   |
|       |               |                   |              |
|       +---------------+-------------------+              |
|                       v                                  |
|              +-----------------+                         |
|              |  grpcapi.Service |  Transport-agnostic     |
|              |  (business logic)|  API layer              |
|              +--------+--------+                         |
|                       v                                  |
|              +-----------------+                         |
|              |   core.Engine   |  Wires all subsystems    |
|              +--------+--------+                         |
|       +-------+-------+-------+-------+-------+         |
|       v       v       v       v       v       v         |
|  +--------+ +-----+ +-----+ +-----+ +-----+ +----+     |
|  |Identity| |Sess.| |Graph| |Modul| |Audit| |Vault|    |
|  | Broker | |Stack| |Store| |Runnr| | Log | |     |    |
|  +--------+ +-----+ +-----+ +-----+ +-----+ +----+     |
|       |       |       |       |       |       |         |
|       +-------+-------+-------+-------+       |         |
|                       v                       v         |
|              +-----------------+     +-------------+     |
|              |    SQLite DBs   |     |  Encrypted   |    |
|              | metadata + audit|     |  Vault File  |    |
|              +-----------------+     +-------------+     |
|                       |                                  |
|                       v                                  |
|              +-----------------+                         |
|              |  AWS SDK v2     |  Rate limited,           |
|              |  Adapter Layer  |  cached, audit-logged    |
|              +-----------------+                         |
+---------------------------------------------------------+
```

- **Core Engine** (`core.Engine`) -- Wires MetadataDB, AuditDB, Vault, AuditLogger, and Workspace
- **Service Layer** (`grpcapi.Service`) -- 45+ methods shared by CLI, GUI, and teamserver
- **Storage** -- SQLite for metadata + audit, AES-256-GCM encrypted vault for secrets
- **AWS Adapter** -- SDK v2 with per-service rate limiting, TTL response caching, and audit logging

## Prerequisites

| Dependency | Version | Notes |
|------------|---------|-------|
| Go | 1.23+ | toolchain 1.24.7; CGO required (sqlite3) |
| Node.js | 18+ | For GUI frontend build |
| C compiler | any | Xcode CLT on macOS, gcc on Linux (for sqlite3) |

Wails CLI and npm packages are installed automatically by `make setup`.

## Getting Started

```bash
# One-time setup -- installs Wails CLI, Go modules, npm packages, verifies CGO
make setup

# Verify your toolchain any time
make check
```

## Building

```bash
# Build everything (CLI + teamserver + GUI) in one command
make build

# Build CLI + teamserver only (no frontend, fast)
make quick

# Individual targets
make build-cli              # -> bin/stratus
make build-server           # -> bin/stratus-server
make build-gui              # -> cmd/stratus-gui/build/bin/

# Run tests (15 packages)
make test

# Cross-compile CLI for Linux/macOS/Windows
make build-all

# See all available targets
make help
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

# 5. Analyze privilege escalation paths
stratus run com.stratus.iam.policy-analyzer
stratus run com.stratus.codebuild.privesc-check

# 6. Discover attack chains
stratus pivot graph build
stratus pivot attack-paths
stratus pivot attack-paths --target "*AdminRole*" --severity critical

# 7. Explore the pivot graph
stratus pivot hops               # Show reachable nodes from current identity
stratus pivot path --to arn:aws:iam::123456789012:role/Admin
stratus pivot assume arn:aws:iam::123456789012:role/LateralTarget

# 8. Manage context stack (push before pivoting, pop to return)
stratus sessions push <session-uuid>
stratus sessions peek
stratus sessions pop

# 9. Collect evidence
stratus artifacts list
stratus artifacts create evidence.json --label "API response" --type json_result
stratus artifacts verify          # SHA-256 integrity check

# 10. Export
stratus export --format json --output ./evidence/
stratus export --format markdown --output ./report/
```

## GUI

The STRATUS GUI is a native desktop application (Wails v2) providing a full operator console.

### Running

```bash
# Development mode with hot reload (from repo root -- no cd needed)
make dev

# Production build
make build-gui
```

### Views

| View | Description |
|------|-------------|
| **Dashboard** | Workspace overview, stat cards (identities, sessions, graph nodes, module runs), scope display, recent runs table, audit chain health |
| **Identities** | Filterable identity table, detail panel with linked sessions, import dialog (IAM Key, STS Session, IMDS, Credential Process, Assume Role, Web Identity), archive action |
| **Sessions** | Session list with health badges, LIFO stack visualization from `PeekStack()`, activate/push/pop/expire/refresh actions, STS whoami verification |
| **Modules** | Card grid with search + service + risk class filters, module detail panel (inputs, required IAM actions, references), run dialog with auto-generated input forms, dry-run toggle, destructive operation warnings |
| **PrivEsc** | Privilege escalation analysis results from `iam.policy-analyzer` with severity filtering, principal risk summary, and detailed finding breakdown |
| **Role Chains** | Recursive role chain discovery results from `sts.enumerate-roles-chain` with chain depth visualization |
| **Attack Paths** | Attack path analysis with ranked chain list, expandable step-by-step exploitation detail, severity filtering, score visualization, and high-value target identification |
| **Graph** | D3.js force-directed pivot graph with zoom/pan/drag, node coloring by type (IAM user, role, service, account root), edge styling by relationship, path finder, node detail sidebar |
| **Audit** | Audit chain verification banner, event type filter, paginated event table (50/page), expandable JSON detail per event |
| **Artifacts** | Content-addressed artifact browser with integrity verification, type filtering, and content preview |
| **Notes** | Engagement notes linked to sessions, runs, or graph nodes with create/edit/delete |
| **AWS Explorer** | Direct AWS API access for ad-hoc operations across 13 services |

### GUI Architecture

The GUI is a thin Wails wrapper around the same `grpcapi.Service` layer that backs the CLI and teamserver. The `App` struct in `cmd/stratus-gui/app.go` delegates all operations to the service -- no business logic duplication. Wails auto-generates TypeScript bindings from the exported Go methods.

```
cmd/stratus-gui/
  main.go              Wails entrypoint (embeds frontend/dist)
  app.go               App struct: ~50 bound methods -> grpcapi.Service
  wails.json           Wails v2 configuration
  frontend/
    src/
      App.tsx           Root component, workspace state, routing
      views/            12 views (Dashboard, Identities, Sessions, Modules, PrivEsc,
                        Role Chains, Attack Paths, Graph, Audit, Artifacts, Notes,
                        AWS Explorer)
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
| `pivot assume/graph/hops/path/can-i/attack-paths` | Lateral movement, pivot graph, and attack path analysis |
| `run <module-id>` | Execute modules with `--dry-run` and `--preflight` |
| `modules search/list/info` | Browse available modules |
| `runs list/show` | View module execution history |
| `scope show/update/check` | Blast radius scope management |
| `artifacts list/show/create/get/verify` | Content-addressed artifact storage |
| `note add/list/show/update/delete` | Engagement note management |
| `export --format json/markdown` | Evidence export |
| `aws <service> <operation>` | Convenience AWS API wrappers (sts, iam, s3, ec2, eks, lambda, cloudtrail, kms, logs, ssm, secretsmanager, codebuild, cognito) |
| `awsraw` | Direct AWS API access escape hatch |

## Built-in Modules

### Reconnaissance (read_only)

| ID | Name | Services | Description |
|----|------|----------|-------------|
| `com.stratus.iam.enumerate-roles` | Enumerate IAM Roles | IAM | Lists roles, parses trust policies, populates pivot graph with `can_assume` edges |
| `com.stratus.iam.enumerate-users` | Enumerate IAM Users | IAM | Lists users with group memberships, policies, access keys, MFA status |
| `com.stratus.iam.policy-analyzer` | IAM Privilege Escalation Analyzer | IAM | Detects 20+ privilege escalation patterns (PassRole, PutUserPolicy, AttachRolePolicy, etc.) |
| `com.stratus.sts.enumerate-roles-chain` | Recursive Role Chain Discovery | STS, IAM | Depth-limited BFS through assumable roles, builds comprehensive lateral movement pivot graph |
| `com.stratus.s3.find-public-buckets` | Find Public S3 Buckets | S3 | Scans buckets for public access (ACL + policy analysis) |
| `com.stratus.s3.exfil-check` | S3 Exfiltration Check | S3 | Assesses bucket-level data access controls, encryption config, and exfiltration risk |
| `com.stratus.ec2.enumerate-instances` | Enumerate EC2 Instances | EC2 | Lists instances across regions with security group mappings |
| `com.stratus.ec2.security-group-audit` | Security Group Audit | EC2 | Identifies security groups with overly permissive ingress rules |
| `com.stratus.ec2.userdata-extract` | Extract EC2 User Data | EC2 | Extracts instance user data containing bootstrap scripts, embedded credentials, and config |
| `com.stratus.ebs.enumerate-snapshots` | Enumerate EBS Snapshots | EC2 | Lists account-owned EBS snapshots, identifies unencrypted snapshots for data extraction |
| `com.stratus.lambda.enumerate-functions` | Enumerate Lambda Functions | Lambda | Lists functions with runtime, memory, VPC config |
| `com.stratus.lambda.extract-env-vars` | Extract Lambda Env Vars | Lambda | Retrieves Lambda environment variables, flags sensitive-looking credentials and API keys |
| `com.stratus.cloudtrail.status` | CloudTrail Config Audit | CloudTrail | Audits trail configuration, multi-region settings, logging status |
| `com.stratus.cloudwatch.enumerate-logs` | Enumerate CloudWatch Log Groups | CloudWatch | Lists log groups with retention and data volume, assesses monitoring posture |
| `com.stratus.kms.key-inventory` | KMS Key Inventory | KMS | Inventories KMS keys with rotation status and key policies |
| `com.stratus.secretsmanager.enumerate` | Enumerate Secrets Manager | SecretsManager | Lists secrets, optionally retrieves values to identify exposed credentials and API keys |
| `com.stratus.ssm.enumerate-parameters` | Enumerate SSM Parameters | SSM | Lists Parameter Store entries, identifies SecureString parameters containing credentials |
| `com.stratus.rds.enumerate-instances` | Enumerate RDS Instances | RDS | Lists RDS instances and snapshots, identifies publicly accessible and unencrypted databases |
| `com.stratus.dynamodb.enumerate-tables` | Enumerate DynamoDB Tables | DynamoDB | Lists tables with item counts, size, encryption status, and table class |
| `com.stratus.ecs.enumerate-clusters` | Enumerate ECS Clusters | ECS | Lists clusters and running tasks, identifies task IAM roles for lateral movement |
| `com.stratus.sns.enumerate-topics` | Enumerate SNS Topics | SNS | Lists topics with access policies, identifies overly permissive public/cross-account access |
| `com.stratus.mwaa.enumerate` | Enumerate MWAA Environments | MWAA | Lists managed Airflow environments with execution roles, VPC configs, and DAG storage |
| `com.stratus.sagemaker.enumerate` | Enumerate SageMaker Resources | SageMaker | Lists notebooks, training jobs, endpoints with IAM roles and network configs |
| `com.stratus.config.enumerate` | Enumerate AWS Config | Config | Lists Config recorders, delivery channels, and compliance status |
| `com.stratus.codebuild.enumerate` | Enumerate CodeBuild Projects | CodeBuild | Lists projects with service roles, env vars, source configs, webhooks, and recent builds. Flags plaintext secrets and weak webhook filters |
| `com.stratus.cognito.enumerate` | Enumerate Cognito Pools | Cognito | Enumerates User Pools (clients, groups, IdPs, MFA) and Identity Pools (role mappings, unauthenticated access, classic flow) |
| `com.stratus.eks.enumerate` | Enumerate EKS Clusters | EKS | Lists clusters with API endpoint access, OIDC/IRSA providers, node groups, Fargate profiles, and logging config |

### Privilege Escalation Analysis (read_only)

| ID | Name | Services | Description |
|----|------|----------|-------------|
| `com.stratus.sagemaker.privesc-check` | SageMaker Privilege Escalation Check | SageMaker | Identifies SageMaker privesc paths (notebook presigned URLs, training job role assumption, endpoint invocation) |
| `com.stratus.codebuild.privesc-check` | CodeBuild Privilege Escalation Check | CodeBuild | Identifies 7 CodeBuild privesc techniques: buildspec override, role swapping, S3 backdoor, webhook exploitation, privileged container escape |
| `com.stratus.cognito.privesc-check` | Cognito Privilege Escalation Check | Cognito | Identifies 12 Cognito privesc techniques: unauthenticated credential theft, role swapping, user impersonation, MFA bypass |
| `com.stratus.eks.privesc-check` | EKS Privilege Escalation Check | EKS | Identifies 16 EKS privesc techniques across AWS and Kubernetes layers: aws-auth takeover, IRSA abuse, pod escape, IMDS theft |

### Attack Path Analysis (read_only, local-only)

| ID | Name | Services | Description |
|----|------|----------|-------------|
| `com.stratus.attackpath.analyze` | Attack Path Analyzer | IAM, STS | Correlates pivot graph edges with privilege escalation findings from prior module runs to identify and rank exploitable attack chains. Zero AWS API calls -- reads only from local SQLite. Outputs ranked chains with step-by-step exploitation instructions. |

### Offensive (write / destructive)

| ID | Name | Risk | Description |
|----|------|------|-------------|
| `com.stratus.iam.create-access-key` | Create IAM Access Key | write | Creates a new access key for a target IAM user |
| `com.stratus.ec2.modify-security-group` | Modify Security Group | write | Adds ingress rules to a security group |
| `com.stratus.cloudtrail.stop-trail` | Stop CloudTrail Logging | destructive | Stops a CloudTrail trail (defense evasion) |
| `com.stratus.iam.backdoor-role` | Backdoor IAM Role Trust Policy | destructive | Modifies a role's trust policy to add an attacker-controlled principal for persistence |

All write/destructive modules include mandatory dry-run logging, scope enforcement, and audit chain recording.

## Attack Path Analysis

The attack path analyzer is a post-reconnaissance correlation engine. It combines data from the pivot graph (IAM trust relationships) and privilege escalation module outputs to identify exploitable chains from your current identity to high-value targets.

### How It Works

1. **BFS reachability** -- Traverses `can_assume` graph edges from the current identity to build a set of all reachable roles
2. **Privesc correlation** -- Loads findings from prior runs of `iam.policy-analyzer`, `codebuild.privesc-check`, `cognito.privesc-check`, `sagemaker.privesc-check`, and `eks.privesc-check`
3. **Chain construction** -- For each reachable role with privesc findings, builds a multi-step chain (assume hops + exploit step)
4. **Scoring** -- Ranks chains by `(confidence * severity_bonus) / (1 + 0.1 * hops)`, with admin target bonus
5. **Output** -- Ranked chains with step-by-step exploitation instructions, required IAM actions, and confidence scores

### Usage

```bash
# Run prereqs first
stratus pivot graph build
stratus run com.stratus.iam.policy-analyzer
stratus run com.stratus.codebuild.privesc-check

# Analyze attack paths
stratus pivot attack-paths
stratus pivot attack-paths --target "*AdminRole*" --severity critical --depth 3
stratus pivot attack-paths --json
```

The GUI Attack Paths view provides the same analysis with an interactive chain browser, expandable step detail, and score visualization.

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

The teamserver exposes the full STRATUS API over gRPC using a JSON-RPC dispatch pattern. Each operator authenticates with an ECDSA P-256 client certificate signed by the engagement CA. All 45+ operations (workspace, identity, session, graph, module, audit, notes, scope, attack path analysis) are available remotely.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Secrets at rest** | AES-256-GCM encryption, Argon2id key derivation (vault passphrase) |
| **Transport** | mTLS with ECDSA P-256 certificates, TLS 1.3 minimum |
| **Audit integrity** | Append-only SHA-256 hash chain (tamper detection) |
| **Blast radius** | 4-layer scope enforcement: module runner -> AWS adapter -> CLI commands -> pivot operations |
| **Artifact integrity** | SHA-256 content-addressed storage with verification |
| **Secret redaction** | Structured logging with automatic credential masking |

## Project Structure

```
cmd/
  stratus/                CLI binary (Cobra) -- 12 command files
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
  module/                 Module registry, runner, and 36 built-in modules
  pki/                    mTLS certificate authority and certificate generation
  logging/                Structured logging with secret redaction
  aws/                    AWS SDK v2 adapter (rate limiting, retry, caching, audit logging)
  config/                 Global and workspace configuration
  grpcapi/                Transport-agnostic API service layer + JSON-RPC handler
pkg/
  sdk/v1/                 Module developer SDK interface
```

**Codebase stats:** ~30,500 lines Go across 93 files, ~5,400 lines TypeScript across 26 frontend files, 15 test packages passing.

## Development

```bash
# GUI development with hot reload
make dev

# Run all tests with race detection
make test

# Run tests with coverage
make test-coverage

# Format and vet
make fmt
make vet

# Lint (requires golangci-lint)
make lint

# See all available targets
make help
```

There is also a standalone dev script for users who don't use `make`:

```bash
./scripts/dev.sh            # Check deps, auto-install npm packages, start wails dev
./scripts/dev.sh --cli      # Quick CLI build
./scripts/dev.sh --server   # Quick teamserver build
```

### Key development patterns

- **Engine pattern** -- `core.Engine` wires all subsystems; CLI uses `loadActiveEngine()`, GUI uses `core.OpenWorkspace()`
- **Service layer** -- `grpcapi.Service` contains all business logic; CLI/GUI/teamserver are thin wrappers
- **Sessions are immutable** -- Refresh creates a new `SessionRecord` with `ChainParentSessionUUID`
- **Vault persistence** -- Must call `vault.Save()` after `vault.Put()` to persist to disk
- **ClientFactory credentials** -- Call `SetDefaultCredentials()` before module execution; modules create region-only creds and the factory merges the secret material
- **Trust policies** -- AWS API returns URL-encoded trust policy documents; must `url.QueryUnescape` before parsing
- **Adding a new module** -- Implement `sdk.Module` in `internal/module/mod_<name>.go`, register in `RegisterBuiltinModules()` in `registry.go`
- **Adding a GUI view** -- Create component in `views/`, add route in `App.tsx`, add nav link in `Sidebar.tsx`, add Go binding in `app.go` if needed

## License

Proprietary -- Authorized security testing use only.
