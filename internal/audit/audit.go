// Package audit provides the append-only audit logging system for STRATUS.
// Audit records form a hash chain for tamper detection.
package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// EventType categorizes audit log entries.
type EventType string

const (
	EventAPICall          EventType = "api_call"
	EventSessionActivated EventType = "session_activated"
	EventIdentityImported EventType = "identity_imported"
	EventScopeViolation   EventType = "scope_violation"
	EventSecretShared     EventType = "secret_shared"
	EventModuleRun        EventType = "module_run"
	EventWorkspaceCreated EventType = "workspace_created"
	EventSessionExpired   EventType = "session_expired"
)

// Logger writes tamper-evident audit records to the audit database.
type Logger struct {
	db            *sql.DB
	mu            sync.Mutex
	lastHash      string
	workspaceUUID string
}

// NewLogger creates an audit logger for the given workspace.
func NewLogger(db *sql.DB, workspaceUUID string) (*Logger, error) {
	al := &Logger{
		db:            db,
		workspaceUUID: workspaceUUID,
	}

	// Recover last hash for chain continuity
	var lastHash sql.NullString
	err := db.QueryRow(
		"SELECT record_hash FROM audit_log WHERE workspace_uuid = ? ORDER BY id DESC LIMIT 1",
		workspaceUUID,
	).Scan(&lastHash)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("recovering audit chain: %w", err)
	}
	if lastHash.Valid {
		al.lastHash = lastHash.String
	}

	return al, nil
}

// Log writes an audit event. The record is appended immutably with a hash chain.
func (al *Logger) Log(eventType EventType, operator, sessionUUID, runUUID string, detail any) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	detailJSON, err := json.Marshal(detail)
	if err != nil {
		detailJSON = []byte(fmt.Sprintf(`{"error":"failed to marshal detail: %s"}`, err))
	}

	now := time.Now().UTC()
	recordHash := al.computeHash(now, eventType, operator, string(detailJSON))

	_, err = al.db.Exec(
		`INSERT INTO audit_log (timestamp, workspace_uuid, session_uuid, run_uuid, operator, event_type, detail, record_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		now.Format(time.RFC3339Nano),
		al.workspaceUUID,
		sessionUUID,
		runUUID,
		operator,
		string(eventType),
		string(detailJSON),
		recordHash,
	)
	if err != nil {
		return fmt.Errorf("inserting audit record: %w", err)
	}

	al.lastHash = recordHash
	return nil
}

// computeHash creates the hash chain link: SHA-256(previousHash + timestamp + eventType + operator + detail)
func (al *Logger) computeHash(ts time.Time, eventType EventType, operator, detail string) string {
	data := al.lastHash + ts.Format(time.RFC3339Nano) + string(eventType) + operator + detail
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// Verify checks the integrity of the audit chain for a workspace.
func Verify(db *sql.DB, workspaceUUID string) (bool, int, error) {
	rows, err := db.Query(
		"SELECT timestamp, event_type, operator, detail, record_hash FROM audit_log WHERE workspace_uuid = ? ORDER BY id ASC",
		workspaceUUID,
	)
	if err != nil {
		return false, 0, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var previousHash string
	count := 0

	for rows.Next() {
		var ts, eventType, operator, detail, recordHash string
		if err := rows.Scan(&ts, &eventType, &operator, &detail, &recordHash); err != nil {
			return false, count, fmt.Errorf("scanning audit row: %w", err)
		}

		data := previousHash + ts + eventType + operator + detail
		h := sha256.Sum256([]byte(data))
		expected := hex.EncodeToString(h[:])

		if expected != recordHash {
			return false, count, fmt.Errorf("audit chain broken at record %d", count+1)
		}

		previousHash = recordHash
		count++
	}

	return true, count, nil
}
