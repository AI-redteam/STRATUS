// Package session manages the session lifecycle and LIFO context stack.
package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/core"
)

// Manager handles session operations: listing, activation, context stack, health.
type Manager struct {
	db            *sql.DB
	audit         *audit.Logger
	workspaceUUID string
}

// NewManager creates a session manager for the given workspace.
func NewManager(db *sql.DB, al *audit.Logger, workspaceUUID string) *Manager {
	return &Manager{
		db:            db,
		audit:         al,
		workspaceUUID: workspaceUUID,
	}
}

// ListSessions returns all sessions in the workspace.
func (m *Manager) ListSessions() ([]core.SessionRecord, error) {
	rows, err := m.db.Query(
		`SELECT uuid, identity_uuid, aws_access_key_id, session_name, region, expiry,
		        refresh_method, refresh_config_ref, chain_parent_session_uuid,
		        created_at, last_verified_at, health_status, is_active, workspace_uuid
		 FROM sessions WHERE workspace_uuid = ? ORDER BY created_at DESC`,
		m.workspaceUUID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying sessions: %w", err)
	}
	defer rows.Close()

	return scanSessions(rows)
}

// GetSession retrieves a session by UUID or session name.
func (m *Manager) GetSession(uuidOrLabel string) (*core.SessionRecord, error) {
	rows, err := m.db.Query(
		`SELECT uuid, identity_uuid, aws_access_key_id, session_name, region, expiry,
		        refresh_method, refresh_config_ref, chain_parent_session_uuid,
		        created_at, last_verified_at, health_status, is_active, workspace_uuid
		 FROM sessions WHERE workspace_uuid = ? AND (uuid = ? OR session_name = ?) LIMIT 1`,
		m.workspaceUUID, uuidOrLabel, uuidOrLabel,
	)
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}
	defer rows.Close()

	sessions, err := scanSessions(rows)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("session not found: %s", uuidOrLabel)
	}
	return &sessions[0], nil
}

// GetActiveSession returns the currently active session (top of context stack).
func (m *Manager) GetActiveSession() (*core.SessionRecord, error) {
	rows, err := m.db.Query(
		`SELECT s.uuid, s.identity_uuid, s.aws_access_key_id, s.session_name, s.region, s.expiry,
		        s.refresh_method, s.refresh_config_ref, s.chain_parent_session_uuid,
		        s.created_at, s.last_verified_at, s.health_status, s.is_active, s.workspace_uuid
		 FROM sessions s
		 JOIN context_stack cs ON s.uuid = cs.session_uuid
		 WHERE cs.workspace_uuid = ?
		 ORDER BY cs.position DESC LIMIT 1`,
		m.workspaceUUID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying active session: %w", err)
	}
	defer rows.Close()

	sessions, err := scanSessions(rows)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no active session; use 'stratus sessions use <uuid>' to activate one")
	}
	return &sessions[0], nil
}

// Use activates a session by pushing it onto the context stack.
func (m *Manager) Use(uuidOrLabel string) (*core.SessionRecord, error) {
	session, err := m.GetSession(uuidOrLabel)
	if err != nil {
		return nil, err
	}
	return m.Push(session.UUID)
}

// Push pushes a session onto the context stack.
func (m *Manager) Push(sessionUUID string) (*core.SessionRecord, error) {
	session, err := m.GetSession(sessionUUID)
	if err != nil {
		return nil, err
	}

	// Get next stack position
	var maxPos sql.NullInt64
	m.db.QueryRow(
		"SELECT MAX(position) FROM context_stack WHERE workspace_uuid = ?",
		m.workspaceUUID,
	).Scan(&maxPos)

	nextPos := 0
	if maxPos.Valid {
		nextPos = int(maxPos.Int64) + 1
	}

	now := time.Now().UTC()
	_, err = m.db.Exec(
		"INSERT INTO context_stack (workspace_uuid, session_uuid, pushed_at, position) VALUES (?, ?, ?, ?)",
		m.workspaceUUID, session.UUID, now.Format(time.RFC3339), nextPos,
	)
	if err != nil {
		return nil, fmt.Errorf("pushing to context stack: %w", err)
	}

	// Mark session as active
	m.db.Exec("UPDATE sessions SET is_active = 0 WHERE workspace_uuid = ?", m.workspaceUUID)
	m.db.Exec("UPDATE sessions SET is_active = 1 WHERE uuid = ?", session.UUID)

	m.audit.Log(audit.EventSessionActivated, "local", session.UUID, "", map[string]string{
		"action":       "push",
		"session_uuid": session.UUID,
		"session_name": session.SessionName,
	})

	session.IsActive = true
	return session, nil
}

// Pop removes the top session from the context stack and activates the previous one.
func (m *Manager) Pop() (*core.SessionRecord, error) {
	// Get current top
	var topID int
	var topSessionUUID string
	err := m.db.QueryRow(
		"SELECT id, session_uuid FROM context_stack WHERE workspace_uuid = ? ORDER BY position DESC LIMIT 1",
		m.workspaceUUID,
	).Scan(&topID, &topSessionUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("context stack is empty")
		}
		return nil, fmt.Errorf("reading context stack: %w", err)
	}

	// Remove top
	m.db.Exec("DELETE FROM context_stack WHERE id = ?", topID)
	m.db.Exec("UPDATE sessions SET is_active = 0 WHERE uuid = ?", topSessionUUID)

	// Activate previous (new top)
	var newTopUUID string
	err = m.db.QueryRow(
		"SELECT session_uuid FROM context_stack WHERE workspace_uuid = ? ORDER BY position DESC LIMIT 1",
		m.workspaceUUID,
	).Scan(&newTopUUID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("reading new stack top: %w", err)
	}

	if newTopUUID != "" {
		m.db.Exec("UPDATE sessions SET is_active = 1 WHERE uuid = ?", newTopUUID)
		return m.GetSession(newTopUUID)
	}

	return nil, nil // Stack is now empty
}

// Peek returns the current context stack without modifying it.
func (m *Manager) Peek() ([]core.SessionRecord, error) {
	rows, err := m.db.Query(
		`SELECT s.uuid, s.identity_uuid, s.aws_access_key_id, s.session_name, s.region, s.expiry,
		        s.refresh_method, s.refresh_config_ref, s.chain_parent_session_uuid,
		        s.created_at, s.last_verified_at, s.health_status, s.is_active, s.workspace_uuid
		 FROM sessions s
		 JOIN context_stack cs ON s.uuid = cs.session_uuid
		 WHERE cs.workspace_uuid = ?
		 ORDER BY cs.position DESC`,
		m.workspaceUUID,
	)
	if err != nil {
		return nil, fmt.Errorf("reading context stack: %w", err)
	}
	defer rows.Close()

	return scanSessions(rows)
}

// UpdateHealth updates a session's health status and last verified timestamp.
func (m *Manager) UpdateHealth(sessionUUID string, status core.SessionHealth) error {
	now := time.Now().UTC()
	_, err := m.db.Exec(
		"UPDATE sessions SET health_status = ?, last_verified_at = ? WHERE uuid = ?",
		string(status), now.Format(time.RFC3339), sessionUUID,
	)
	return err
}

// ExpireSession manually marks a session as expired.
func (m *Manager) ExpireSession(sessionUUID string) error {
	now := time.Now().UTC()
	_, err := m.db.Exec(
		"UPDATE sessions SET health_status = ?, expiry = ? WHERE uuid = ?",
		string(core.HealthExpired), now.Format(time.RFC3339), sessionUUID,
	)
	if err != nil {
		return err
	}

	m.audit.Log(audit.EventSessionExpired, "local", sessionUUID, "", map[string]string{
		"action": "manual_expire",
	})
	return nil
}

// CheckExpiry evaluates all sessions and updates health for those past their expiry.
func (m *Manager) CheckExpiry() ([]core.SessionRecord, error) {
	sessions, err := m.ListSessions()
	if err != nil {
		return nil, err
	}

	var expiring []core.SessionRecord
	now := time.Now().UTC()

	for _, s := range sessions {
		if s.Expiry == nil || s.HealthStatus == core.HealthExpired {
			continue
		}
		remaining := s.Expiry.Sub(now)
		if remaining <= 0 {
			m.UpdateHealth(s.UUID, core.HealthExpired)
			s.HealthStatus = core.HealthExpired
			expiring = append(expiring, s)
		} else if remaining <= 15*time.Minute {
			expiring = append(expiring, s)
		}
	}

	return expiring, nil
}

func scanSessions(rows *sql.Rows) ([]core.SessionRecord, error) {
	var sessions []core.SessionRecord
	for rows.Next() {
		var s core.SessionRecord
		var expiry, refreshMethod, refreshConfigRef, chainParent, createdAt, lastVerified sql.NullString
		var isActive int

		err := rows.Scan(
			&s.UUID, &s.IdentityUUID, &s.AWSAccessKeyID, &s.SessionName,
			&s.Region, &expiry, &refreshMethod, &refreshConfigRef,
			&chainParent, &createdAt, &lastVerified,
			&s.HealthStatus, &isActive, &s.WorkspaceUUID,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning session: %w", err)
		}

		if expiry.Valid {
			t, _ := time.Parse(time.RFC3339, expiry.String)
			s.Expiry = &t
		}
		if refreshMethod.Valid {
			rm := refreshMethod.String
			s.RefreshMethod = &rm
		}
		if refreshConfigRef.Valid {
			s.RefreshConfigRef = refreshConfigRef.String
		}
		if chainParent.Valid {
			cp := chainParent.String
			s.ChainParentSessionUUID = &cp
		}
		if createdAt.Valid {
			s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
		}
		if lastVerified.Valid {
			t, _ := time.Parse(time.RFC3339, lastVerified.String)
			s.LastVerifiedAt = &t
		}
		s.IsActive = isActive != 0

		sessions = append(sessions, s)
	}
	return sessions, nil
}

// SessionSnapshot creates a serializable snapshot of a session for module run pinning.
func SessionSnapshot(s *core.SessionRecord) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshaling session snapshot: %w", err)
	}
	return string(data), nil
}
