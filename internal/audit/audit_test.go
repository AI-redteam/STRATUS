package audit

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupAuditDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp     TEXT NOT NULL,
		workspace_uuid TEXT NOT NULL,
		session_uuid  TEXT DEFAULT '',
		run_uuid      TEXT DEFAULT '',
		operator      TEXT NOT NULL DEFAULT 'local',
		event_type    TEXT NOT NULL,
		detail        TEXT DEFAULT '{}',
		record_hash   TEXT NOT NULL
	)`)
	if err != nil {
		t.Fatalf("creating table: %v", err)
	}

	return db
}

func TestLogAndVerify(t *testing.T) {
	db := setupAuditDB(t)
	defer db.Close()

	logger, err := NewLogger(db, "ws-test")
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	// Log several events
	logger.Log(EventAPICall, "local", "sess-1", "", map[string]string{"service": "sts"})
	logger.Log(EventModuleRun, "local", "sess-1", "run-1", map[string]string{"module": "test"})
	logger.Log(EventIdentityImported, "local", "", "", map[string]string{"label": "test"})

	// Verify chain
	valid, count, err := Verify(db, "ws-test")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("expected valid chain")
	}
	if count != 3 {
		t.Errorf("expected 3 records, got %d", count)
	}
}

func TestChainTamperDetection(t *testing.T) {
	db := setupAuditDB(t)
	defer db.Close()

	logger, err := NewLogger(db, "ws-test")
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	logger.Log(EventAPICall, "local", "", "", map[string]string{"a": "1"})
	logger.Log(EventAPICall, "local", "", "", map[string]string{"b": "2"})
	logger.Log(EventAPICall, "local", "", "", map[string]string{"c": "3"})

	// Tamper with a record
	db.Exec("UPDATE audit_log SET detail = '{\"tampered\":true}' WHERE id = 2")

	valid, _, err := Verify(db, "ws-test")
	if err == nil {
		t.Error("expected error from tampered chain")
	}
	if valid {
		t.Error("expected invalid chain after tampering")
	}
}

func TestEmptyChainIsValid(t *testing.T) {
	db := setupAuditDB(t)
	defer db.Close()

	valid, count, err := Verify(db, "ws-test")
	if err != nil {
		t.Fatalf("verify empty: %v", err)
	}
	if !valid {
		t.Error("expected empty chain to be valid")
	}
	if count != 0 {
		t.Errorf("expected 0 records, got %d", count)
	}
}

func TestNewLoggerRecoversPreviousHash(t *testing.T) {
	db := setupAuditDB(t)
	defer db.Close()

	// Create first logger and log an event
	logger1, _ := NewLogger(db, "ws-test")
	logger1.Log(EventAPICall, "local", "", "", map[string]string{"first": "event"})

	// Create second logger (simulates restart)
	logger2, _ := NewLogger(db, "ws-test")
	logger2.Log(EventModuleRun, "local", "", "", map[string]string{"second": "event"})

	// Chain should still be valid
	valid, count, err := Verify(db, "ws-test")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("expected valid chain after logger recovery")
	}
	if count != 2 {
		t.Errorf("expected 2 records, got %d", count)
	}
}
