# STRATUS Backlog

Prioritized list of planned work beyond the v1 MVP.

## Legend

- **P0** — Critical / next up
- **P1** — High priority, planned for near-term
- **P2** — Medium priority, design needed
- **P3** — Nice to have / future

---

## GUI Enhancements

- [ ] **P0** — Workspace creation from GUI (currently CLI only)
- [ ] **P0** — Assume role from GUI (pivot assume dialog with role ARN selector from graph)
- [ ] **P0** — Session refresh from GUI (call existing session refresh logic)
- [ ] **P1** — Dashboard stat cards should link to their respective views
- [ ] **P1** — Module run progress indicator (real-time progress from Go → frontend)
- [ ] **P1** — Graph: right-click context menu on nodes (assume role, view detail, copy ARN)
- [ ] **P1** — Graph: edge labels on hover (edge type + confidence percentage)
- [ ] **P1** — Graph: auto-layout options (hierarchical, radial, force-directed toggle)
- [ ] **P1** — Audit view: export filtered events as JSON/CSV
- [ ] **P2** — Notes view as standalone tab (currently only accessible via detail panels)
- [ ] **P2** — Dark/light theme toggle
- [ ] **P2** — Keyboard shortcuts (Ctrl+1-6 for views, Escape to close panels)
- [ ] **P2** — Toast notifications for async operations (import success, module complete)
- [ ] **P3** — Artifact viewer (preview JSON artifacts inline, download binary artifacts)
- [ ] **P3** — Module run diff (compare outputs between two runs of the same module)

## Modules

- [ ] **P0** — `com.stratus.sts.enumerate-roles-chain` — Recursive role assumption chain discovery (depth-limited BFS through assumable roles)
- [ ] **P1** — `com.stratus.iam.policy-analyzer` — Analyze IAM policies for privilege escalation paths (iam:PassRole, sts:AssumeRole, lambda:CreateFunction, etc.)
- [ ] **P1** — `com.stratus.s3.exfil-check` — Test S3 bucket data access (list objects, read sample, check encryption)
- [ ] **P1** — `com.stratus.secretsmanager.enumerate` — List and optionally retrieve Secrets Manager secrets
- [ ] **P1** — `com.stratus.ssm.enumerate-parameters` — List SSM Parameter Store entries
- [ ] **P2** — `com.stratus.ec2.userdata-extract` — Extract EC2 instance user data (credential harvesting)
- [ ] **P2** — `com.stratus.lambda.invoke-function` — Invoke Lambda functions with custom payloads (write)
- [ ] **P2** — `com.stratus.iam.backdoor-role` — Create or modify role trust policy (destructive)
- [ ] **P3** — Plugin loading from `.so`/`.dylib` files (extend beyond built-in modules)
- [ ] **P3** — Module marketplace / community registry

## Core Framework

- [ ] **P0** — Session auto-refresh (background goroutine, configurable interval)
- [ ] **P1** — Credential process import (`aws credential_process` compatible)
- [ ] **P1** — Web identity token import (OIDC → STS)
- [ ] **P1** — Scope: ARN-pattern enforcement (currently only region + account + partition)
- [ ] **P1** — Module input validation (enforce required fields, type checking before execution)
- [ ] **P2** — Workspace merge (combine two workspace DBs from split engagements)
- [ ] **P2** — Graph: edge aging and automatic stale marking (configurable TTL)
- [ ] **P2** — Graph: Dijkstra pathfinding weighted by confidence scores (currently BFS)
- [ ] **P2** — Artifact tagging and search
- [ ] **P3** — Undo/rollback for write operations (snapshot before, restore after)

## Teamserver

- [ ] **P1** — Protobuf code generation (replace JSON-RPC dispatch with proper gRPC stubs)
- [ ] **P1** — Operator presence (who's connected, what session they're using)
- [ ] **P1** — Real-time event streaming (gRPC server-side streaming for audit events, module progress)
- [ ] **P2** — Role-based access control (read-only observers vs. full operators)
- [ ] **P2** — Teamserver CLI client (`stratus connect --server teamserver.internal:9443 --cert operator.pem`)
- [ ] **P3** — Multi-workspace support (single teamserver, multiple engagements)
- [ ] **P3** — Webhook integrations (Slack/Discord notifications on module completion)

## Distribution & CI/CD

- [ ] **P1** — CI/CD pipeline (GitHub Actions: build, test, lint, release on tag)
- [ ] **P1** — GitHub Releases with pre-built binaries via goreleaser (CLI + GUI per platform)
- [ ] **P2** — Homebrew tap for macOS (`brew install stratus`)
- [ ] **P2** — `.deb` / `.rpm` packages for Linux
- [ ] **P2** — Docker image for teamserver (`docker run stratus-server serve ...`)
- [ ] **P3** — Wails v3 migration (when stable — update Makefile/scripts accordingly)

## Testing & Quality

- [ ] **P0** — Integration tests for module execution (mock AWS responses with httptest)
- [ ] **P1** — GUI component tests (React Testing Library)
- [ ] **P1** — End-to-end test: workspace create → import identity → run module → verify artifact
- [ ] **P1** — Fuzz testing for trust policy parser
- [ ] **P2** — Benchmark tests for graph pathfinding at scale (1000+ nodes)

## Documentation

- [ ] **P1** — Module developer guide (SDK interface, input/output specs, graph mutations)
- [ ] **P1** — Engagement playbook template (step-by-step for common AWS pentest scenarios)
- [ ] **P2** — Architecture deep-dive document
- [ ] **P2** — Teamserver deployment guide (Docker, systemd, certificates)
- [ ] **P3** — Video walkthrough of full engagement workflow
