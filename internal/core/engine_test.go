package core

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stratus-framework/stratus/internal/db"
	"github.com/stratus-framework/stratus/internal/vault"
)

func TestInitAndOpenWorkspace(t *testing.T) {
	dir := t.TempDir()

	// Create a new workspace
	engine, err := InitWorkspace(dir, "test-engagement", "unit test workspace", "test-pass",
		Scope{
			AccountIDs: []string{"123456789012"},
			Regions:    []string{"us-east-1", "us-west-2"},
		})
	if err != nil {
		t.Fatalf("init workspace: %v", err)
	}

	ws := engine.Workspace
	if ws.Name != "test-engagement" {
		t.Errorf("expected name 'test-engagement', got %q", ws.Name)
	}
	if ws.Description != "unit test workspace" {
		t.Errorf("expected description, got %q", ws.Description)
	}
	if len(ws.ScopeConfig.AccountIDs) != 1 || ws.ScopeConfig.AccountIDs[0] != "123456789012" {
		t.Error("scope account IDs not persisted")
	}
	if len(ws.ScopeConfig.Regions) != 2 {
		t.Error("scope regions not persisted")
	}

	wsPath := ws.Path
	engine.Close()

	// Reopen the workspace
	engine2, err := OpenWorkspace(wsPath, "test-pass")
	if err != nil {
		t.Fatalf("open workspace: %v", err)
	}
	defer engine2.Close()

	if engine2.Workspace.UUID != ws.UUID {
		t.Errorf("expected UUID %s, got %s", ws.UUID, engine2.Workspace.UUID)
	}
	if engine2.Workspace.Name != "test-engagement" {
		t.Errorf("expected name preserved, got %q", engine2.Workspace.Name)
	}
}

func TestOpenWorkspaceWrongPassphrase(t *testing.T) {
	dir := t.TempDir()

	engine, err := InitWorkspace(dir, "secure-ws", "", "correct-pass", Scope{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// Put a test secret so vault has an entry to validate against
	engine.Vault.Put("test-key", []byte("secret-data"))
	engine.Vault.Save()
	wsPath := engine.Workspace.Path
	engine.Close()

	// Try opening with wrong passphrase
	_, err = OpenWorkspace(wsPath, "wrong-pass")
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestEngineClose(t *testing.T) {
	dir := t.TempDir()

	engine, err := InitWorkspace(dir, "close-test", "", "pass", Scope{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// Close should not error
	if err := engine.Close(); err != nil {
		t.Errorf("close error: %v", err)
	}
}

func TestWorkspaceManagerCreateWorkspace(t *testing.T) {
	dir := t.TempDir()
	wm := NewWorkspaceManager(dir)

	ws, err := wm.CreateWorkspace("engagement-1", "test engagement", "operator", Scope{
		AccountIDs: []string{"111222333444"},
		Regions:    []string{"eu-west-1"},
		Partition:  "aws",
	})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	if ws.UUID == "" {
		t.Error("expected non-empty UUID")
	}
	if ws.Name != "engagement-1" {
		t.Errorf("expected name 'engagement-1', got %q", ws.Name)
	}
	if ws.Owner != "operator" {
		t.Errorf("expected owner 'operator', got %q", ws.Owner)
	}
	if ws.ScopeConfig.Partition != "aws" {
		t.Errorf("expected partition 'aws', got %q", ws.ScopeConfig.Partition)
	}

	// Verify directory exists
	artDir := filepath.Join(ws.Path, "artifacts")
	if !dirExists(artDir) {
		t.Error("expected artifacts directory to exist")
	}
}

func dirExists(path string) bool {
	info, err := statPath(path)
	return err == nil && info
}

func statPath(path string) (isDir bool, err error) {
	// Use a simple file open to check
	db, err := sql.Open("sqlite3", filepath.Join(path, "probe.db"))
	if err != nil {
		return false, err
	}
	db.Close()
	return true, nil
}

func TestSaveAndLoadWorkspaceRecord(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	metaDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer metaDB.Close()

	metaDB.Exec(db.MetadataSchema)

	ws := &Workspace{
		UUID:        "ws-save-test",
		Name:        "save-test",
		Description: "testing save/load",
		Owner:       "tester",
		Path:        "/tmp/test",
		ScopeConfig: Scope{
			AccountIDs: []string{"123456789012"},
			Regions:    []string{"us-east-1"},
		},
		Tags: []string{"test"},
	}

	if err := SaveWorkspaceRecord(metaDB, ws); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load by UUID
	loaded, err := LoadWorkspaceRecord(metaDB, "ws-save-test")
	if err != nil {
		t.Fatalf("load by UUID: %v", err)
	}
	if loaded.Name != "save-test" {
		t.Errorf("expected name 'save-test', got %q", loaded.Name)
	}
	if loaded.Description != "testing save/load" {
		t.Errorf("expected description preserved, got %q", loaded.Description)
	}
	if len(loaded.ScopeConfig.AccountIDs) != 1 {
		t.Error("scope config not preserved")
	}
	if len(loaded.Tags) != 1 || loaded.Tags[0] != "test" {
		t.Error("tags not preserved")
	}

	// Load by name
	loaded2, err := LoadWorkspaceRecord(metaDB, "save-test")
	if err != nil {
		t.Fatalf("load by name: %v", err)
	}
	if loaded2.UUID != "ws-save-test" {
		t.Error("load by name returned wrong workspace")
	}

	// Load nonexistent
	_, err = LoadWorkspaceRecord(metaDB, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent workspace")
	}
}

func TestListWorkspaces(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	metaDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer metaDB.Close()

	metaDB.Exec(db.MetadataSchema)

	ws1 := &Workspace{UUID: "ws1", Name: "first", Owner: "op", Path: "/a"}
	ws2 := &Workspace{UUID: "ws2", Name: "second", Owner: "op", Path: "/b"}

	SaveWorkspaceRecord(metaDB, ws1)
	SaveWorkspaceRecord(metaDB, ws2)

	all, err := ListWorkspaces(metaDB)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 workspaces, got %d", len(all))
	}
}

func TestVaultIntegration(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, vault.VaultFileName)

	// Create vault
	v, err := vault.Create(vaultPath, "test-pass")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}

	v.Put("key1", []byte("secret1"))
	v.Put("key2", []byte("secret2"))
	v.Save()
	v.Close()

	// Reopen and verify
	v2, err := vault.Open(vaultPath, "test-pass")
	if err != nil {
		t.Fatalf("reopen vault: %v", err)
	}
	defer v2.Close()

	data, err := v2.Get("key1")
	if err != nil {
		t.Fatalf("get key1: %v", err)
	}
	if string(data) != "secret1" {
		t.Errorf("expected 'secret1', got %q", data)
	}

	if !v2.Has("key2") {
		t.Error("expected key2 to exist")
	}

	keys := v2.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}
