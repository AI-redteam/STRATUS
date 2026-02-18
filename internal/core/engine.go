// engine.go provides the central Engine that wires together all STRATUS subsystems.
package core

import (
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/db"
	"github.com/stratus-framework/stratus/internal/logging"
	"github.com/stratus-framework/stratus/internal/vault"
)

// Engine is the central coordinator for all STRATUS subsystems.
type Engine struct {
	Workspace   *Workspace
	MetadataDB  *sql.DB
	AuditDB     *sql.DB
	Vault       *vault.Vault
	AuditLogger *audit.Logger
	Logger      zerolog.Logger
}

// OpenWorkspace opens an existing workspace, unlocking the vault with the given passphrase.
func OpenWorkspace(wsPath string, passphrase string) (*Engine, error) {
	// Open metadata database
	metaDB, err := db.OpenMetadataDB(wsPath)
	if err != nil {
		return nil, fmt.Errorf("opening metadata database: %w", err)
	}

	// Open audit database
	auditDB, err := db.OpenAuditDB(wsPath)
	if err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("opening audit database: %w", err)
	}

	// Load workspace record
	ws, err := LoadWorkspaceRecord(metaDB, filepath.Base(wsPath))
	if err != nil {
		// Try loading by path
		rows, qerr := metaDB.Query("SELECT uuid FROM workspaces LIMIT 1")
		if qerr != nil {
			metaDB.Close()
			auditDB.Close()
			return nil, fmt.Errorf("loading workspace: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			var uuid string
			rows.Scan(&uuid)
			ws, err = LoadWorkspaceRecord(metaDB, uuid)
			if err != nil {
				metaDB.Close()
				auditDB.Close()
				return nil, fmt.Errorf("loading workspace by uuid: %w", err)
			}
		} else {
			metaDB.Close()
			auditDB.Close()
			return nil, fmt.Errorf("no workspace found in database at %s", wsPath)
		}
	}

	// Open encrypted vault
	vaultPath := filepath.Join(wsPath, vault.VaultFileName)
	v, err := vault.Open(vaultPath, passphrase)
	if err != nil {
		metaDB.Close()
		auditDB.Close()
		return nil, fmt.Errorf("opening vault: %w", err)
	}

	// Create audit logger
	al, err := audit.NewLogger(auditDB, ws.UUID)
	if err != nil {
		v.Close()
		metaDB.Close()
		auditDB.Close()
		return nil, fmt.Errorf("creating audit logger: %w", err)
	}

	logger := logging.NewLogger("info", ws.UUID)

	return &Engine{
		Workspace:   ws,
		MetadataDB:  metaDB,
		AuditDB:     auditDB,
		Vault:       v,
		AuditLogger: al,
		Logger:      logger,
	}, nil
}

// InitWorkspace creates a new workspace with all necessary databases and vault.
func InitWorkspace(basePath, name, description, passphrase string, scope Scope) (*Engine, error) {
	wm := NewWorkspaceManager(basePath)
	ws, err := wm.CreateWorkspace(name, description, "local", scope)
	if err != nil {
		return nil, err
	}

	// Initialize metadata database
	metaDB, err := db.OpenMetadataDB(ws.Path)
	if err != nil {
		return nil, fmt.Errorf("creating metadata database: %w", err)
	}

	// Save workspace record
	if err := SaveWorkspaceRecord(metaDB, ws); err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("saving workspace record: %w", err)
	}

	// Initialize audit database
	auditDB, err := db.OpenAuditDB(ws.Path)
	if err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("creating audit database: %w", err)
	}

	// Create encrypted vault
	vaultPath := filepath.Join(ws.Path, vault.VaultFileName)
	v, err := vault.Create(vaultPath, passphrase)
	if err != nil {
		metaDB.Close()
		auditDB.Close()
		return nil, fmt.Errorf("creating vault: %w", err)
	}

	// Create audit logger
	al, err := audit.NewLogger(auditDB, ws.UUID)
	if err != nil {
		v.Close()
		metaDB.Close()
		auditDB.Close()
		return nil, fmt.Errorf("creating audit logger: %w", err)
	}

	// Log workspace creation
	al.Log(audit.EventWorkspaceCreated, "local", "", "", map[string]string{
		"workspace_uuid": ws.UUID,
		"name":           name,
	})

	logger := logging.NewLogger("info", ws.UUID)

	return &Engine{
		Workspace:   ws,
		MetadataDB:  metaDB,
		AuditDB:     auditDB,
		Vault:       v,
		AuditLogger: al,
		Logger:      logger,
	}, nil
}

// Close cleanly shuts down all engine resources.
func (e *Engine) Close() error {
	var firstErr error
	if e.Vault != nil {
		if err := e.Vault.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.MetadataDB != nil {
		if err := e.MetadataDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.AuditDB != nil {
		if err := e.AuditDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
