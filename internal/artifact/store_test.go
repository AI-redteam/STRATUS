package artifact

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stratus-framework/stratus/internal/core"
)

func setupTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}

	// Create artifacts table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS artifacts (
		uuid            TEXT PRIMARY KEY,
		workspace_uuid  TEXT NOT NULL,
		run_uuid        TEXT,
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
	)`)
	if err != nil {
		t.Fatalf("creating table: %v", err)
	}

	artDir := filepath.Join(dir, "artifacts")
	os.MkdirAll(artDir, 0700)

	return db, dir
}

func TestStoreCreate(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")

	content := []byte(`{"roles": ["admin", "viewer"]}`)
	art, err := store.Create(CreateInput{
		SessionUUID:  "sess-123",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "test output",
		Content:      content,
		CreatedBy:    "test",
		Tags:         []string{"test", "json"},
	})
	if err != nil {
		t.Fatalf("creating artifact: %v", err)
	}

	if art.UUID == "" {
		t.Error("expected non-empty UUID")
	}
	if art.ByteSize != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), art.ByteSize)
	}

	// Verify content hash
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])
	if art.ContentHash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, art.ContentHash)
	}

	// Verify file exists on disk
	filePath := filepath.Join(dir, "artifacts", art.StoragePath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("expected artifact file to exist on disk")
	}
}

func TestStoreReadContent(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")
	content := []byte("hello world artifact content")

	art, err := store.Create(CreateInput{
		SessionUUID:  "sess-123",
		ArtifactType: core.ArtifactAPIProof,
		Label:        "proof",
		Content:      content,
		CreatedBy:    "test",
	})
	if err != nil {
		t.Fatalf("creating artifact: %v", err)
	}

	// Read back
	data, err := store.ReadContent(art)
	if err != nil {
		t.Fatalf("reading content: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q", data)
	}
}

func TestStoreContentDedup(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")
	content := []byte("duplicate content")

	art1, _ := store.Create(CreateInput{
		SessionUUID:  "sess-1",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "first",
		Content:      content,
		CreatedBy:    "test",
	})

	art2, _ := store.Create(CreateInput{
		SessionUUID:  "sess-2",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "second",
		Content:      content,
		CreatedBy:    "test",
	})

	// Different UUIDs
	if art1.UUID == art2.UUID {
		t.Error("expected different UUIDs for deduped artifacts")
	}

	// Same hash and storage path (content dedup)
	if art1.ContentHash != art2.ContentHash {
		t.Error("expected same content hash")
	}
	if art1.StoragePath != art2.StoragePath {
		t.Error("expected same storage path (dedup)")
	}
}

func TestStoreGet(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")
	content := []byte("get test")

	created, _ := store.Create(CreateInput{
		SessionUUID:  "sess-123",
		ArtifactType: core.ArtifactNote,
		Label:        "get-test",
		Content:      content,
		CreatedBy:    "test",
	})

	// Get by full UUID
	got, err := store.Get(created.UUID)
	if err != nil {
		t.Fatalf("get by UUID: %v", err)
	}
	if got.Label != "get-test" {
		t.Errorf("expected label 'get-test', got %q", got.Label)
	}

	// Get by prefix
	got, err = store.Get(created.UUID[:8])
	if err != nil {
		t.Fatalf("get by prefix: %v", err)
	}
	if got.UUID != created.UUID {
		t.Error("prefix match returned wrong artifact")
	}

	// Get nonexistent
	_, err = store.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent artifact")
	}
}

func TestStoreList(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")

	store.Create(CreateInput{SessionUUID: "s1", ArtifactType: core.ArtifactJSONResult, Label: "a", Content: []byte("1"), CreatedBy: "test"})
	store.Create(CreateInput{SessionUUID: "s1", ArtifactType: core.ArtifactJSONResult, Label: "b", Content: []byte("2"), CreatedBy: "test"})
	store.Create(CreateInput{SessionUUID: "s2", ArtifactType: core.ArtifactJSONResult, Label: "c", Content: []byte("3"), CreatedBy: "test"})

	// List all
	all, err := store.List("", "")
	if err != nil {
		t.Fatalf("listing all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}

	// List by session
	filtered, err := store.List("", "s1")
	if err != nil {
		t.Fatalf("listing filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Errorf("expected 2 for session s1, got %d", len(filtered))
	}
}

func TestStoreVerifyIntegrity(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")

	art, _ := store.Create(CreateInput{
		SessionUUID:  "sess-1",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "verify",
		Content:      []byte("integrity test"),
		CreatedBy:    "test",
	})

	// Should be valid
	valid, invalid, err := store.VerifyIntegrity()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if valid != 1 || len(invalid) != 0 {
		t.Errorf("expected 1 valid, 0 invalid; got %d valid, %d invalid", valid, len(invalid))
	}

	// Corrupt the file
	corruptPath := filepath.Join(dir, "artifacts", art.StoragePath)
	os.WriteFile(corruptPath, []byte("corrupted!"), 0600)

	valid, invalid, err = store.VerifyIntegrity()
	if err != nil {
		t.Fatalf("verify after corruption: %v", err)
	}
	if valid != 0 || len(invalid) != 1 {
		t.Errorf("expected 0 valid, 1 invalid; got %d valid, %d invalid", valid, len(invalid))
	}
}

func TestStoreSensitiveFlag(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()

	store := NewStore(db, dir, "ws-test-uuid")

	art, _ := store.Create(CreateInput{
		SessionUUID:  "sess-1",
		ArtifactType: core.ArtifactAPIProof,
		Label:        "sensitive",
		Content:      []byte("secret data"),
		CreatedBy:    "test",
		IsSensitive:  true,
	})

	got, _ := store.Get(art.UUID)
	if !got.IsSensitive {
		t.Error("expected artifact to be marked sensitive")
	}
}
