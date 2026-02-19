package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stratus-framework/stratus/internal/config"
	"github.com/stratus-framework/stratus/internal/core"
	stratusdb "github.com/stratus-framework/stratus/internal/db"
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
		metaPath := filepath.Join(wsPath, stratusdb.MetadataDBFile)
		if _, err := os.Stat(metaPath); err != nil {
			continue
		}

		// Try to read workspace name from the DB
		metaDB, err := stratusdb.OpenMetadataDB(wsPath)
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

func (a *App) CreateWorkspace(req grpcapi.CreateWorkspaceRequest) (*grpcapi.WorkspaceInfo, error) {
	// Close any existing workspace first
	if a.engine != nil {
		a.engine.Close()
		a.engine = nil
		a.service = nil
	}

	engine, info, err := grpcapi.CreateWorkspace(req)
	if err != nil {
		return nil, err
	}

	// Auto-open the newly created workspace
	a.engine = engine
	a.service = grpcapi.NewService(engine)
	return info, nil
}

// --- Scope management ---

func (a *App) UpdateScope(req grpcapi.UpdateScopeRequest) (*grpcapi.ScopeInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.UpdateScope(req)
}

func (a *App) CheckScope(region, accountID string) *grpcapi.ScopeCheckResult {
	if a.service == nil {
		return &grpcapi.ScopeCheckResult{InScope: false, Reason: "no workspace open"}
	}
	return a.service.CheckScope(region, accountID)
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

func (a *App) ImportIAMKey(req grpcapi.ImportIAMKeyRequest) (*grpcapi.ImportIAMKeyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportIAMKey(req)
}

func (a *App) ImportSTSSession(req grpcapi.ImportSTSSessionRequest) (*grpcapi.ImportIAMKeyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportSTSSession(req)
}

func (a *App) ArchiveIdentity(uuidOrLabel string) error {
	if err := a.requireWorkspace(); err != nil {
		return err
	}
	return a.service.ArchiveIdentity(uuidOrLabel)
}

func (a *App) ImportIMDS(req grpcapi.ImportIMDSRequest) (*grpcapi.ImportIAMKeyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportIMDS(req)
}

func (a *App) ImportCredProcess(req grpcapi.ImportCredProcessRequest) (*grpcapi.ImportIAMKeyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportCredProcess(req)
}

func (a *App) ImportAssumeRoleIdentity(req grpcapi.ImportAssumeRoleRequest) (*grpcapi.ImportIdentityOnlyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportAssumeRoleIdentity(req)
}

func (a *App) ImportWebIdentity(req grpcapi.ImportWebIdentityRequest) (*grpcapi.ImportIdentityOnlyResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ImportWebIdentity(req)
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

// --- Session intelligence ---

func (a *App) SessionWhoami(uuid string) (*grpcapi.WhoamiResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.SessionWhoami(uuid)
}

func (a *App) SessionHealthCheck() ([]grpcapi.SessionHealthResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.SessionHealthCheck()
}

func (a *App) RefreshSession(uuid string) (*grpcapi.SessionInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.RefreshSession(uuid)
}

func (a *App) PivotAssume(req grpcapi.PivotAssumeRequest) (*grpcapi.PivotAssumeResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.PivotAssume(req)
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

// --- Artifacts ---

func (a *App) ListArtifacts(runFilter, typeFilter string) ([]grpcapi.ArtifactInfo, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ListArtifacts(runFilter, typeFilter)
}

func (a *App) GetArtifact(uuid string) (*grpcapi.ArtifactContent, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.GetArtifact(uuid)
}

func (a *App) VerifyArtifacts() (*grpcapi.VerifyArtifactsResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.VerifyArtifacts()
}

// --- Export ---

func (a *App) ExportWorkspace(req grpcapi.ExportRequest) (*grpcapi.ExportResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.ExportWorkspace(req)
}

// --- AWS Explorer ---

func (a *App) AWSExplore(req grpcapi.AWSExplorerRequest) (*grpcapi.AWSExplorerResult, error) {
	if err := a.requireWorkspace(); err != nil {
		return nil, err
	}
	return a.service.AWSExplore(a.ctx, req)
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
