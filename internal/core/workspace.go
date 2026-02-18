// workspace.go implements workspace lifecycle operations.
package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// WorkspaceManager handles workspace CRUD operations.
type WorkspaceManager struct {
	basePath string // Base directory where workspaces are stored
}

// NewWorkspaceManager creates a workspace manager using the given base directory.
func NewWorkspaceManager(basePath string) *WorkspaceManager {
	return &WorkspaceManager{basePath: basePath}
}

// CreateWorkspace creates a new workspace directory and metadata record.
func (wm *WorkspaceManager) CreateWorkspace(name, description, owner string, scope Scope) (*Workspace, error) {
	wsUUID := uuid.New().String()
	wsPath := filepath.Join(wm.basePath, wsUUID)

	now := time.Now().UTC()
	ws := &Workspace{
		UUID:        wsUUID,
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
		Owner:       owner,
		ScopeConfig: scope,
		Path:        wsPath,
	}

	// Create workspace directory
	if err := os.MkdirAll(wsPath, 0700); err != nil {
		return nil, fmt.Errorf("creating workspace directory: %w", err)
	}

	// Create subdirectories
	for _, sub := range []string{"artifacts", "plugins", "snapshots"} {
		if err := os.MkdirAll(filepath.Join(wsPath, sub), 0700); err != nil {
			return nil, fmt.Errorf("creating %s directory: %w", sub, err)
		}
	}

	return ws, nil
}

// SaveWorkspaceRecord persists workspace metadata to the database.
func SaveWorkspaceRecord(db *sql.DB, ws *Workspace) error {
	scopeJSON, err := json.Marshal(ws.ScopeConfig)
	if err != nil {
		return fmt.Errorf("marshaling scope: %w", err)
	}

	tagsJSON, err := json.Marshal(ws.Tags)
	if err != nil {
		tagsJSON = []byte("[]")
	}

	_, err = db.Exec(
		`INSERT OR REPLACE INTO workspaces (uuid, name, description, created_at, updated_at, owner, tags, scope_config, encryption_key_hint, path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ws.UUID, ws.Name, ws.Description,
		ws.CreatedAt.Format(time.RFC3339),
		ws.UpdatedAt.Format(time.RFC3339),
		ws.Owner, string(tagsJSON), string(scopeJSON),
		ws.EncryptionKeyHint, ws.Path,
	)
	return err
}

// LoadWorkspaceRecord reads workspace metadata from the database.
func LoadWorkspaceRecord(db *sql.DB, uuidOrName string) (*Workspace, error) {
	var ws Workspace
	var tagsJSON, scopeJSON, createdAt, updatedAt string

	err := db.QueryRow(
		`SELECT uuid, name, description, created_at, updated_at, owner, tags, scope_config, encryption_key_hint, path
		 FROM workspaces WHERE uuid = ? OR name = ? LIMIT 1`,
		uuidOrName, uuidOrName,
	).Scan(
		&ws.UUID, &ws.Name, &ws.Description,
		&createdAt, &updatedAt,
		&ws.Owner, &tagsJSON, &scopeJSON,
		&ws.EncryptionKeyHint, &ws.Path,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workspace not found: %s", uuidOrName)
		}
		return nil, err
	}

	ws.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	ws.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	json.Unmarshal([]byte(tagsJSON), &ws.Tags)
	json.Unmarshal([]byte(scopeJSON), &ws.ScopeConfig)

	return &ws, nil
}

// ListWorkspaces returns all workspaces from the index database.
func ListWorkspaces(db *sql.DB) ([]Workspace, error) {
	rows, err := db.Query(
		`SELECT uuid, name, description, created_at, updated_at, owner, tags, scope_config, encryption_key_hint, path
		 FROM workspaces ORDER BY updated_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []Workspace
	for rows.Next() {
		var ws Workspace
		var tagsJSON, scopeJSON, createdAt, updatedAt string
		err := rows.Scan(
			&ws.UUID, &ws.Name, &ws.Description,
			&createdAt, &updatedAt,
			&ws.Owner, &tagsJSON, &scopeJSON,
			&ws.EncryptionKeyHint, &ws.Path,
		)
		if err != nil {
			return nil, err
		}
		ws.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		ws.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		json.Unmarshal([]byte(tagsJSON), &ws.Tags)
		json.Unmarshal([]byte(scopeJSON), &ws.ScopeConfig)
		workspaces = append(workspaces, ws)
	}
	return workspaces, nil
}
