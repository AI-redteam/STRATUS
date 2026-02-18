package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stratus-framework/stratus/internal/config"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/db"
	"github.com/stratus-framework/stratus/internal/grpcapi"
)

var errNoWorkspace = fmt.Errorf("no workspace is open")

// App is the Wails application struct. All exported methods are bound
// to the frontend as callable functions.
type App struct {
	ctx     context.Context
	engine  *core.Engine
	service *grpcapi.Service
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(_ context.Context) {
	if a.engine != nil {
		a.engine.Close()
	}
}

func (a *App) requireWorkspace() error {
	if a.service == nil {
		return errNoWorkspace
	}
	return nil
}

// --- Workspace lifecycle ---

// WorkspaceEntry is a lightweight workspace listing item.
type WorkspaceEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func (a *App) ListWorkspaces() ([]WorkspaceEntry, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(cfg.WorkspacesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []WorkspaceEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		wsPath := filepath.Join(cfg.WorkspacesDir, entry.Name())
		metaPath := filepath.Join(wsPath, "metadata.db")
		if _, err := os.Stat(metaPath); err != nil {
			continue
		}

		// Try to read workspace name from the DB
		metaDB, err := db.OpenMetadataDB(wsPath)
		if err != nil {
			continue
		}
		var name string
		metaDB.QueryRow("SELECT name FROM workspaces LIMIT 1").Scan(&name)
		metaDB.Close()

		if name == "" {
			name = entry.Name()
		}
		result = append(result, WorkspaceEntry{
			UUID: entry.Name(),
			Name: name,
			Path: wsPath,
		})
	}
	return result, nil
}

func (a *App) OpenWorkspace(path, passphrase string) error {
	if a.engine != nil {
		a.engine.Close()
		a.engine = nil
		a.service = nil
	}

	engine, err := core.OpenWorkspace(path, passphrase)
	if err != nil {
		return err
	}

	a.engine = engine
	a.service = grpcapi.NewService(engine)
	return nil
}

func (a *App) CloseWorkspace() {
	if a.engine != nil {
		a.engine.Close()
		a.engine = nil
		a.service = nil
	}
}

func (a *App) IsWorkspaceOpen() bool {
	return a.service != nil
}

// --- Workspace info ---

func (a *App) GetWorkspace() (*grpcapi.WorkspaceInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetWorkspace(), nil
}

// --- Identity ---

func (a *App) ListIdentities() ([]grpcapi.IdentityInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListIdentities()
}

func (a *App) GetIdentity(uuidOrLabel string) (*grpcapi.IdentityInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetIdentity(uuidOrLabel)
}

func (a *App) ArchiveIdentity(uuidOrLabel string) error {
	if err := a.requireWorkspace(); err != nil {
		return err
	}
	return a.service.ArchiveIdentity(uuidOrLabel)
}

// --- Sessions ---

func (a *App) ListSessions() ([]grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListSessions()
}

func (a *App) GetActiveSession() (*grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetActiveSession()
}

func (a *App) ActivateSession(uuidOrLabel string) (*grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ActivateSession(uuidOrLabel)
}

func (a *App) PushSession(uuidOrLabel string) (*grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.PushSession(uuidOrLabel)
}

func (a *App) PopSession() (*grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.PopSession()
}

func (a *App) PeekStack() ([]grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.PeekStack()
}

func (a *App) ExpireSession(uuid string) error {
	if err := a.requireWorkspace(); err != nil {
		return err
	}
	return a.service.ExpireSession(uuid)
}

// --- Graph ---

func (a *App) FindPath(from, to string) (*grpcapi.GraphPathResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.FindPath(from, to)
}

func (a *App) GetHops(fromNodeID string) ([]grpcapi.GraphEdgeInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetHops(fromNodeID)
}

func (a *App) GetGraphStats() (*grpcapi.GraphStats, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetGraphStats()
}

func (a *App) GetGraphSnapshot() (string, error) {
	if err := a.requireWorkspace(); err != nil {
		return "", err
	}
	return a.service.GetGraphSnapshot()
}

// --- Modules ---

func (a *App) ListModules(keyword, service, riskClass string) []grpcapi.ModuleInfo {
	if a.service == nil {
		return nil
	}
	return a.service.ListModules(keyword, service, riskClass)
}

func (a *App) RunModule(req grpcapi.RunModuleRequest) (*grpcapi.RunModuleResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.RunModule(a.ctx, req)
}

func (a *App) GetRunStatus(runUUID string) (*grpcapi.RunInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetRunStatus(runUUID)
}

func (a *App) ListRuns(moduleFilter, statusFilter string) ([]grpcapi.RunInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListRuns(moduleFilter, statusFilter)
}

// --- Audit ---

func (a *App) VerifyAuditChain() (map[string]any, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	valid, count, err := a.service.VerifyAuditChain()
	if err != nil {
		return nil, err
	}
	return map[string]any{"valid": valid, "count": count}, nil
}

func (a *App) ListAuditEvents(limit, offset int, eventTypeFilter string) ([]grpcapi.AuditEntry, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListAuditEvents(limit, offset, eventTypeFilter)
}

// --- Scope ---

func (a *App) GetScopeInfo() (*grpcapi.ScopeInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetScopeInfo(), nil
}

// --- Notes ---

func (a *App) ListNotes(sessionFilter, runFilter, nodeFilter string) ([]grpcapi.NoteInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListNotes(sessionFilter, runFilter, nodeFilter)
}

func (a *App) GetNote(uuidOrPrefix string) (*grpcapi.NoteInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetNote(uuidOrPrefix)
}

func (a *App) AddNote(req grpcapi.AddNoteRequest) (*grpcapi.NoteInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.AddNote(req)
}

func (a *App) UpdateNote(uuidOrPrefix, newContent string) error {
	if err := a.requireWorkspace(); err != nil {
		return err
	}
	return a.service.UpdateNote(uuidOrPrefix, newContent)
}

func (a *App) DeleteNote(uuidOrPrefix string) error {
	if err := a.requireWorkspace(); err != nil {
		return err
	}
	return a.service.DeleteNote(uuidOrPrefix)
}
