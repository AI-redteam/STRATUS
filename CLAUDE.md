# STRATUS — Claude Code Session Guide

This file preps Claude Code sessions to work effectively on this repo.

## What is STRATUS?

AWS adversary emulation & security testing framework. Go backend, React/TypeScript GUI, gRPC teamserver. Think Metasploit for AWS cloud — centralized identity management, pivot graphing, modular operations, audit trail.

**Authorized security testing context only.**

## Build & Test

```bash
# Build everything (requires CGO for sqlite3)
go build ./...

# Run all tests (15 packages, ~20 tests)
go test ./...

# GUI frontend (requires Node.js 18+)
cd cmd/stratus-gui/frontend && npm install && npx vite build

# GUI dev mode (requires Wails v2: go install github.com/wailsapp/wails/v2/cmd/wails@latest)
cd cmd/stratus-gui && wails dev

# Quick verify after changes
go build ./... && go test ./... && cd cmd/stratus-gui/frontend && npx vite build
```

**Always run `go build ./...` and `go test ./...` after Go changes. Always run `npx vite build` after frontend changes.**

## Architecture (key files)

### Core engine + primitives
- `internal/core/types.go` — All core types (Workspace, SessionRecord, GraphEdge, ModuleRun, etc.)
- `internal/core/engine.go` — Engine struct wires MetadataDB, AuditDB, Vault, AuditLogger, Workspace

### Service layer (the API)
- `internal/grpcapi/service.go` — **THE business logic layer.** 30+ methods shared by CLI, GUI, and teamserver. All new features go here first.
- `internal/grpcapi/handler.go` — JSON-RPC dispatch for teamserver; register new service methods here too.

### CLI
- `cmd/stratus/cli/` — 12 Cobra command files; `helpers.go` has `loadActiveEngine()`, `aws.go` has `awsClientSetup()`
- `cmd/stratus/main.go` — Wires all commands

### GUI (Wails v2 + React)
- `cmd/stratus-gui/app.go` — ~35 thin delegation methods from Wails → `grpcapi.Service`. Add new GUI methods here.
- `cmd/stratus-gui/frontend/src/hooks/useWails.ts` — TypeScript wrappers for Go bindings. Add matching TS calls here.
- `cmd/stratus-gui/frontend/src/types/api.ts` — TypeScript interfaces mirroring Go types. Keep in sync.
- `cmd/stratus-gui/frontend/src/views/` — 6 view components (Dashboard, Identities, Sessions, Modules, Graph, Audit)

### Subsystems
- `internal/identity/` — Credential import broker (7 methods)
- `internal/session/` — LIFO session stack manager
- `internal/graph/` — SQLite pivot graph + BFS pathfinding
- `internal/module/` — Module registry + runner + 11 built-in modules
- `internal/aws/` — SDK v2 adapter with rate limiting, caching, audit logging
- `internal/vault/` — AES-256-GCM encrypted vault (Argon2id KDF)
- `internal/audit/` — Append-only SHA-256 hash chain
- `internal/artifact/` — Content-addressed file store
- `internal/scope/` — Blast radius enforcement
- `internal/db/schema.go` — Full SQLite schema (12 tables)

### Module SDK
- `pkg/sdk/v1/module.go` — Module interface, RunContext, InputSpec, OutputSpec, RunResult

## Patterns to follow

### Adding a new service method
1. Add the method to `internal/grpcapi/service.go`
2. Add handler entry in `internal/grpcapi/handler.go` dispatch map
3. Add wrapper in `cmd/stratus-gui/app.go` (guarded by `requireWorkspace()`)
4. Add TypeScript call in `frontend/src/hooks/useWails.ts`
5. Add TypeScript types in `frontend/src/types/api.ts` if new types needed

### Adding a new module
1. Create `internal/module/mod_<name>.go` implementing `sdk.Module` interface
2. Register in `RegisterBuiltinModules()` at bottom of `internal/module/registry.go`
3. Module gets a `*aws.ClientFactory` and optionally `*graph.Store`
4. Module's `Run()` creates `aws.SessionCredentials{Region: ctx.Session.Region}` — the factory fills in actual creds via `SetDefaultCredentials()` (set by the runner before execution)
5. Use `sdk.ErrResult(err)` for errors, return `sdk.RunResult{Outputs: map[string]any{...}}` for success
6. If module discovers graph relationships, call `m.graph.AddNode()` for ALL referenced nodes, then `m.graph.AddEdge()` for edges

### Adding a new GUI view
1. Create component in `frontend/src/views/`
2. Add route in `frontend/src/App.tsx`
3. Add nav link in `frontend/src/components/layout/Sidebar.tsx`
4. Use shared components: `DataTable`, `DetailPanel`, `Badge`, `LoadingState`, `ErrorBanner`

## Common gotchas

- **ClientFactory credentials**: Modules create creds with only Region set. The runner calls `factory.SetDefaultCredentials(creds)` before execution to inject the real secret material. If you see auth failures in modules, check this.
- **Vault persistence**: Must call `vault.Save()` after `vault.Put()`. Forgetting this loses secrets.
- **Trust policies URL-encoded**: AWS API returns URL-encoded trust policy documents. Always `url.QueryUnescape()` before JSON parsing.
- **Graph nodes required for edges**: D3 force-link crashes (NaN propagation → WebKit crash) if edges reference node IDs that don't exist. Always `AddNode()` for both source and target before `AddEdge()`.
- **SQLite NOT NULL columns**: Check `internal/db/schema.go` before writing INSERT statements. Missing columns cause runtime errors (e.g., `session_snapshot` in `module_runs`).
- **Wails error format**: Go errors may arrive as plain strings in JS, not objects with `.message`. Always handle: `typeof e === 'string' ? e : (e?.message || String(e))`
- **CGO required**: sqlite3 driver needs CGO enabled. `CGO_ENABLED=0` builds will fail.
- **Frontend rebuild**: After TypeScript changes, run `npx vite build` in `cmd/stratus-gui/frontend/`. Wails embeds `frontend/dist/`.

## Code style

- Go: standard gofmt, no external linter config required
- TypeScript: React functional components, hooks pattern, Tailwind CSS utility classes
- Dark theme: `stratus-bg: #0F172A`, `stratus-surface: #1E293B`, `stratus-accent: #38BDF8`
- No emojis in code or docs unless explicitly requested
- Keep solutions minimal — don't add abstractions for single-use patterns
- Module IDs follow reverse-domain: `com.stratus.<service>.<action>`

## Current state (v1 MVP)

- CLI: complete (12 command files, 11 modules, full feature set)
- GUI: complete (6 views, identity import, module execution, pivot graph, audit viewer)
- Teamserver: complete (gRPC + mTLS, JSON-RPC dispatch, all service methods)
- Tests: 15 packages passing, zero TODOs/FIXMEs
- See `BACKLOG.md` for planned work
