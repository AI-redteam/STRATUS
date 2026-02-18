package session

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/core"
)

const wsUUID = "ws-test-uuid"

func setupTestDB(t *testing.T) (*sql.DB, *audit.Logger) {
	t.Helper()
	dir := t.TempDir()

	// Metadata DB
	db, err := sql.Open("sqlite3", filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}

	db.Exec(`CREATE TABLE sessions (
		uuid TEXT PRIMARY KEY, identity_uuid TEXT, aws_access_key_id TEXT DEFAULT '',
		session_name TEXT DEFAULT '', region TEXT DEFAULT 'us-east-1', expiry TEXT,
		refresh_method TEXT, refresh_config_ref TEXT DEFAULT '',
		chain_parent_session_uuid TEXT, created_at TEXT NOT NULL,
		last_verified_at TEXT, health_status TEXT NOT NULL DEFAULT 'unverified',
		is_active INTEGER DEFAULT 0, workspace_uuid TEXT NOT NULL)`)
	db.Exec(`CREATE TABLE context_stack (
		id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_uuid TEXT NOT NULL,
		session_uuid TEXT NOT NULL, pushed_at TEXT NOT NULL, position INTEGER NOT NULL)`)

	// Audit DB
	auditDB, _ := sql.Open("sqlite3", filepath.Join(dir, "audit.db"))
	auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
		workspace_uuid TEXT NOT NULL, session_uuid TEXT DEFAULT '', run_uuid TEXT DEFAULT '',
		operator TEXT NOT NULL DEFAULT 'local', event_type TEXT NOT NULL,
		detail TEXT DEFAULT '{}', record_hash TEXT NOT NULL)`)

	al, _ := audit.NewLogger(auditDB, wsUUID)

	return db, al
}

func insertSession(t *testing.T, db *sql.DB, uuid, name, region string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	db.Exec(`INSERT INTO sessions (uuid, identity_uuid, session_name, region, created_at, health_status, workspace_uuid)
		VALUES (?, 'id-1', ?, ?, ?, 'unverified', ?)`, uuid, name, region, now, wsUUID)
}

func TestListSessions(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "session-one", "us-east-1")
	insertSession(t, db, "s2", "session-two", "us-west-2")

	mgr := NewManager(db, al, wsUUID)
	sessions, err := mgr.ListSessions()
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("expected 2, got %d", len(sessions))
	}
}

func TestGetSession(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "test-session", "us-east-1")

	mgr := NewManager(db, al, wsUUID)

	// By UUID
	s, err := mgr.GetSession("s1")
	if err != nil {
		t.Fatalf("get by UUID: %v", err)
	}
	if s.SessionName != "test-session" {
		t.Errorf("unexpected name: %s", s.SessionName)
	}

	// By name
	s, err = mgr.GetSession("test-session")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if s.UUID != "s1" {
		t.Errorf("unexpected UUID: %s", s.UUID)
	}
}

func TestPushPopPeek(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "first", "us-east-1")
	insertSession(t, db, "s2", "second", "us-east-1")

	mgr := NewManager(db, al, wsUUID)

	// Push first
	_, err := mgr.Push("s1")
	if err != nil {
		t.Fatalf("push s1: %v", err)
	}

	// Push second
	_, err = mgr.Push("s2")
	if err != nil {
		t.Fatalf("push s2: %v", err)
	}

	// Peek - should show s2 on top
	stack, err := mgr.Peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if len(stack) != 2 {
		t.Fatalf("expected stack of 2, got %d", len(stack))
	}
	if stack[0].UUID != "s2" {
		t.Errorf("expected s2 on top, got %s", stack[0].UUID)
	}

	// Active session should be s2
	active, err := mgr.GetActiveSession()
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.UUID != "s2" {
		t.Errorf("expected active s2, got %s", active.UUID)
	}

	// Pop s2, should revert to s1
	prev, err := mgr.Pop()
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if prev == nil {
		t.Fatal("expected previous session after pop")
	}
	if prev.UUID != "s1" {
		t.Errorf("expected s1 after pop, got %s", prev.UUID)
	}
}

func TestUseSession(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "first", "us-east-1")

	mgr := NewManager(db, al, wsUUID)

	s, err := mgr.Use("s1")
	if err != nil {
		t.Fatalf("use: %v", err)
	}
	if s.UUID != "s1" {
		t.Errorf("unexpected UUID: %s", s.UUID)
	}

	active, _ := mgr.GetActiveSession()
	if active.UUID != "s1" {
		t.Errorf("expected s1 active, got %s", active.UUID)
	}
}

func TestUpdateHealth(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "health-test", "us-east-1")

	mgr := NewManager(db, al, wsUUID)

	err := mgr.UpdateHealth("s1", core.HealthHealthy)
	if err != nil {
		t.Fatalf("update health: %v", err)
	}

	s, _ := mgr.GetSession("s1")
	if s.HealthStatus != core.HealthHealthy {
		t.Errorf("expected healthy, got %s", s.HealthStatus)
	}
}

func TestExpireSession(t *testing.T) {
	db, al := setupTestDB(t)
	defer db.Close()

	insertSession(t, db, "s1", "expire-test", "us-east-1")

	mgr := NewManager(db, al, wsUUID)

	err := mgr.ExpireSession("s1")
	if err != nil {
		t.Fatalf("expire: %v", err)
	}

	s, _ := mgr.GetSession("s1")
	if s.HealthStatus != core.HealthExpired {
		t.Errorf("expected expired, got %s", s.HealthStatus)
	}
}
