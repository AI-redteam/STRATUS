package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenMetadataDB(t *testing.T) {
	dir := t.TempDir()

	db, err := OpenMetadataDB(dir)
	if err != nil {
		t.Fatalf("OpenMetadataDB: %v", err)
	}
	defer db.Close()

	// Verify tables exist
	tables := []string{
		"workspaces", "identities", "sessions", "context_stack",
		"graph_edges", "graph_nodes", "module_runs", "artifacts",
		"notes", "module_registry",
	}

	for _, table := range tables {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("Table %s not found: %v", table, err)
		}
	}

	// Verify the db file was created
	if _, err := os.Stat(filepath.Join(dir, MetadataDBFile)); err != nil {
		t.Errorf("DB file not created: %v", err)
	}
}

func TestOpenAuditDB(t *testing.T) {
	dir := t.TempDir()

	db, err := OpenAuditDB(dir)
	if err != nil {
		t.Fatalf("OpenAuditDB: %v", err)
	}
	defer db.Close()

	// Verify audit_log table exists
	var name string
	err = db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'",
	).Scan(&name)
	if err != nil {
		t.Error("audit_log table not found")
	}
}

func TestEnsureWorkspaceDir(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "test-workspace")

	if err := EnsureWorkspaceDir(wsPath); err != nil {
		t.Fatalf("EnsureWorkspaceDir: %v", err)
	}

	expectedDirs := []string{
		wsPath,
		filepath.Join(wsPath, "artifacts"),
		filepath.Join(wsPath, "plugins"),
		filepath.Join(wsPath, "snapshots"),
	}

	for _, d := range expectedDirs {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("Expected directory %s: %v", d, err)
		}
	}
}
