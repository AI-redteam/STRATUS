// Package db provides SQLite database management for STRATUS workspaces.
// Two databases per workspace: stratus.db (metadata) and stratus-audit.db (append-only audit log).
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const (
	MetadataDBFile = "stratus.db"
	AuditDBFile    = "stratus-audit.db"
)

// MetadataSchema defines all tables for the main workspace database.
const MetadataSchema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Workspace metadata
CREATE TABLE IF NOT EXISTS workspaces (
    uuid            TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    owner           TEXT NOT NULL DEFAULT 'local',
    tags            TEXT DEFAULT '[]',  -- JSON array
    scope_config    TEXT DEFAULT '{}',  -- JSON object
    encryption_key_hint TEXT DEFAULT '',
    path            TEXT NOT NULL
);

-- Identity records (credential sources)
CREATE TABLE IF NOT EXISTS identities (
    uuid            TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    account_id      TEXT DEFAULT '',
    principal_arn   TEXT DEFAULT '',
    principal_type  TEXT DEFAULT 'unknown',
    source_type     TEXT NOT NULL,
    vault_key_ref   TEXT NOT NULL,
    acquired_at     TEXT NOT NULL,
    workspace_uuid  TEXT NOT NULL REFERENCES workspaces(uuid),
    tags            TEXT DEFAULT '[]',
    risk_notes      TEXT DEFAULT '',
    is_archived     INTEGER DEFAULT 0,
    created_by      TEXT NOT NULL DEFAULT 'local'
);

CREATE INDEX IF NOT EXISTS idx_identities_workspace ON identities(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_identities_label ON identities(label);
CREATE INDEX IF NOT EXISTS idx_identities_account ON identities(account_id);

-- Session records (immutable STS contexts)
CREATE TABLE IF NOT EXISTS sessions (
    uuid                     TEXT PRIMARY KEY,
    identity_uuid            TEXT NOT NULL REFERENCES identities(uuid),
    aws_access_key_id        TEXT DEFAULT '',
    session_name             TEXT DEFAULT '',
    region                   TEXT DEFAULT 'us-east-1',
    expiry                   TEXT,  -- NULL for long-lived keys
    refresh_method           TEXT,
    refresh_config_ref       TEXT DEFAULT '',
    chain_parent_session_uuid TEXT REFERENCES sessions(uuid),
    created_at               TEXT NOT NULL,
    last_verified_at         TEXT,
    health_status            TEXT NOT NULL DEFAULT 'unverified',
    is_active                INTEGER DEFAULT 0,
    workspace_uuid           TEXT NOT NULL REFERENCES workspaces(uuid)
);

CREATE INDEX IF NOT EXISTS idx_sessions_workspace ON sessions(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions(identity_uuid);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(workspace_uuid, is_active);

-- Context stack (LIFO session stack per workspace)
CREATE TABLE IF NOT EXISTS context_stack (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_uuid  TEXT NOT NULL REFERENCES workspaces(uuid),
    session_uuid    TEXT NOT NULL REFERENCES sessions(uuid),
    pushed_at       TEXT NOT NULL,
    position        INTEGER NOT NULL  -- 0 = bottom of stack
);

CREATE INDEX IF NOT EXISTS idx_context_stack_workspace ON context_stack(workspace_uuid);

-- Pivot graph edges
CREATE TABLE IF NOT EXISTS graph_edges (
    uuid                      TEXT PRIMARY KEY,
    workspace_uuid            TEXT NOT NULL REFERENCES workspaces(uuid),
    source_node_id            TEXT NOT NULL,
    target_node_id            TEXT NOT NULL,
    edge_type                 TEXT NOT NULL,
    evidence_refs             TEXT DEFAULT '[]',
    api_calls_used            TEXT DEFAULT '[]',
    discovered_by_session_uuid TEXT NOT NULL,
    discovered_at             TEXT NOT NULL,
    confidence                REAL NOT NULL DEFAULT 0.0,
    constraints               TEXT DEFAULT '{}',
    is_stale                  INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_graph_source ON graph_edges(source_node_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_target ON graph_edges(target_node_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_workspace_stale ON graph_edges(workspace_uuid, is_stale);

-- Graph nodes (discovered principals and resources)
CREATE TABLE IF NOT EXISTS graph_nodes (
    id                TEXT PRIMARY KEY,  -- ARN or unique resource identifier
    workspace_uuid    TEXT NOT NULL REFERENCES workspaces(uuid),
    node_type         TEXT NOT NULL,  -- iam_user | iam_role | s3_bucket | lambda_function | ...
    label             TEXT DEFAULT '',
    metadata          TEXT DEFAULT '{}',
    discovered_at     TEXT NOT NULL,
    discovered_by_session_uuid TEXT NOT NULL,
    is_stale          INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_workspace ON graph_nodes(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(workspace_uuid, node_type);

-- Module runs
CREATE TABLE IF NOT EXISTS module_runs (
    uuid                     TEXT PRIMARY KEY,
    module_id                TEXT NOT NULL,
    module_version           TEXT DEFAULT '',
    session_uuid             TEXT NOT NULL,
    session_snapshot         TEXT NOT NULL,  -- JSON SessionRecord
    inputs                   TEXT DEFAULT '{}',
    status                   TEXT NOT NULL DEFAULT 'pending',
    started_at               TEXT NOT NULL,
    completed_at             TEXT,
    outputs                  TEXT DEFAULT '{}',
    artifact_uuids           TEXT DEFAULT '[]',
    api_call_log_uuid        TEXT DEFAULT '',
    error_detail             TEXT,
    graph_mutations_applied  TEXT DEFAULT '[]',
    workspace_uuid           TEXT NOT NULL REFERENCES workspaces(uuid),
    created_by               TEXT NOT NULL DEFAULT 'local'
);

CREATE INDEX IF NOT EXISTS idx_runs_workspace ON module_runs(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_runs_module ON module_runs(module_id);
CREATE INDEX IF NOT EXISTS idx_runs_session ON module_runs(session_uuid);
CREATE INDEX IF NOT EXISTS idx_runs_status ON module_runs(status);

-- Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    uuid            TEXT PRIMARY KEY,
    workspace_uuid  TEXT NOT NULL REFERENCES workspaces(uuid),
    run_uuid        TEXT REFERENCES module_runs(uuid),
    session_uuid    TEXT NOT NULL,
    artifact_type   TEXT NOT NULL,
    label           TEXT DEFAULT '',
    content_hash    TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    byte_size       INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT 'local',
    linked_node_ids TEXT DEFAULT '[]',
    tags            TEXT DEFAULT '[]',
    is_sensitive    INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_artifacts_workspace ON artifacts(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_uuid);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_uuid);

-- Notes
CREATE TABLE IF NOT EXISTS notes (
    uuid            TEXT PRIMARY KEY,
    workspace_uuid  TEXT NOT NULL REFERENCES workspaces(uuid),
    session_uuid    TEXT DEFAULT '',
    run_uuid        TEXT DEFAULT '',
    node_id         TEXT DEFAULT '',
    content         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT 'local'
);

CREATE INDEX IF NOT EXISTS idx_notes_workspace ON notes(workspace_uuid);

-- Module registry (cached metadata for loaded modules)
CREATE TABLE IF NOT EXISTS module_registry (
    id              TEXT PRIMARY KEY,  -- com.stratus.iam.enumerate-roles
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    description     TEXT DEFAULT '',
    services        TEXT DEFAULT '[]',
    required_actions TEXT DEFAULT '[]',
    risk_class      TEXT NOT NULL DEFAULT 'read_only',
    signature       TEXT DEFAULT '',
    loaded_at       TEXT NOT NULL,
    source_path     TEXT DEFAULT ''
);
`

// AuditSchema defines the append-only audit log table.
const AuditSchema = `
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    workspace_uuid  TEXT NOT NULL,
    session_uuid    TEXT DEFAULT '',
    run_uuid        TEXT DEFAULT '',
    operator        TEXT NOT NULL DEFAULT 'local',
    event_type      TEXT NOT NULL,
    detail          TEXT DEFAULT '{}',
    record_hash     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_workspace ON audit_log(workspace_uuid);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_uuid);
`

// OpenMetadataDB opens or creates the metadata database for a workspace.
func OpenMetadataDB(workspacePath string) (*sql.DB, error) {
	dbPath := filepath.Join(workspacePath, MetadataDBFile)
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening metadata db: %w", err)
	}

	if _, err := db.Exec(MetadataSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing metadata schema: %w", err)
	}

	return db, nil
}

// OpenAuditDB opens or creates the append-only audit database for a workspace.
func OpenAuditDB(workspacePath string) (*sql.DB, error) {
	dbPath := filepath.Join(workspacePath, AuditDBFile)
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening audit db: %w", err)
	}

	if _, err := db.Exec(AuditSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing audit schema: %w", err)
	}

	return db, nil
}

// EnsureWorkspaceDir creates the workspace directory structure.
func EnsureWorkspaceDir(path string) error {
	dirs := []string{
		path,
		filepath.Join(path, "artifacts"),
		filepath.Join(path, "plugins"),
		filepath.Join(path, "snapshots"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", d, err)
		}
	}
	return nil
}
