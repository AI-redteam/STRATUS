// service.go implements the STRATUS API service layer.
// This is the business logic layer that both gRPC handlers and CLI can use.
package grpcapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/artifact"
	"github.com/stratus-framework/stratus/internal/audit"
	stratusaws "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/identity"
	"github.com/stratus-framework/stratus/internal/module"
	"github.com/stratus-framework/stratus/internal/scope"
	"github.com/stratus-framework/stratus/internal/session"
)

// Service is the unified API service that backs both gRPC and direct CLI access.
type Service struct {
	engine *core.Engine
	logger zerolog.Logger
}

// NewService creates an API service backed by the given engine.
func NewService(engine *core.Engine) *Service {
	return &Service{
		engine: engine,
		logger: engine.Logger,
	}
}

// --- Workspace operations ---

// WorkspaceInfo returns info about the current workspace.
type WorkspaceInfo struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Owner       string   `json:"owner"`
	CreatedAt   string   `json:"created_at"`
	Path        string   `json:"path"`
	Accounts    []string `json:"scope_accounts,omitempty"`
	Regions     []string `json:"scope_regions,omitempty"`
}

func (s *Service) GetWorkspace() *WorkspaceInfo {
	ws := s.engine.Workspace
	return &WorkspaceInfo{
		UUID:        ws.UUID,
		Name:        ws.Name,
		Description: ws.Description,
		Owner:       ws.Owner,
		CreatedAt:   ws.CreatedAt.Format(time.RFC3339),
		Path:        ws.Path,
		Accounts:    ws.ScopeConfig.AccountIDs,
		Regions:     ws.ScopeConfig.Regions,
	}
}

// --- Identity operations ---

// IdentityInfo is a transport-safe identity representation.
type IdentityInfo struct {
	UUID          string `json:"uuid"`
	Label         string `json:"label"`
	SourceType    string `json:"source_type"`
	PrincipalARN  string `json:"principal_arn"`
	PrincipalType string `json:"principal_type"`
	AccountID     string `json:"account_id"`
	AcquiredAt    string `json:"acquired_at"`
}

func (s *Service) ListIdentities() ([]IdentityInfo, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)
	ids, err := broker.ListIdentities()
	if err != nil {
		return nil, err
	}

	var result []IdentityInfo
	for _, id := range ids {
		result = append(result, IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		})
	}
	return result, nil
}

func (s *Service) GetIdentity(uuidOrLabel string) (*IdentityInfo, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)
	id, err := broker.GetIdentity(uuidOrLabel)
	if err != nil {
		return nil, err
	}
	return &IdentityInfo{
		UUID:          id.UUID,
		Label:         id.Label,
		SourceType:    string(id.SourceType),
		PrincipalARN:  id.PrincipalARN,
		PrincipalType: string(id.PrincipalType),
		AccountID:     id.AccountID,
		AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
	}, nil
}

func (s *Service) ArchiveIdentity(uuidOrLabel string) error {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)
	return broker.ArchiveIdentity(uuidOrLabel)
}

// --- Session operations ---

// SessionInfo is a transport-safe session representation.
type SessionInfo struct {
	UUID         string  `json:"uuid"`
	IdentityUUID string  `json:"identity_uuid"`
	SessionName  string  `json:"session_name"`
	Region       string  `json:"region"`
	HealthStatus string  `json:"health_status"`
	Expiry       *string `json:"expiry,omitempty"`
	IsActive     bool    `json:"is_active"`
}

func sessionToInfo(s *core.SessionRecord) SessionInfo {
	info := SessionInfo{
		UUID:         s.UUID,
		IdentityUUID: s.IdentityUUID,
		SessionName:  s.SessionName,
		Region:       s.Region,
		HealthStatus: string(s.HealthStatus),
		IsActive:     s.IsActive,
	}
	if s.Expiry != nil {
		exp := s.Expiry.Format(time.RFC3339)
		info.Expiry = &exp
	}
	return info
}

func (s *Service) ListSessions() ([]SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sessions, err := mgr.ListSessions()
	if err != nil {
		return nil, err
	}

	var result []SessionInfo
	for i := range sessions {
		result = append(result, sessionToInfo(&sessions[i]))
	}
	return result, nil
}

func (s *Service) GetActiveSession() (*SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sess, err := mgr.GetActiveSession()
	if err != nil {
		return nil, err
	}
	info := sessionToInfo(sess)
	return &info, nil
}

func (s *Service) ActivateSession(uuidOrLabel string) (*SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sess, err := mgr.Use(uuidOrLabel)
	if err != nil {
		return nil, err
	}
	info := sessionToInfo(sess)
	return &info, nil
}

func (s *Service) PushSession(uuidOrLabel string) (*SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sess, err := mgr.Push(uuidOrLabel)
	if err != nil {
		return nil, err
	}
	info := sessionToInfo(sess)
	return &info, nil
}

func (s *Service) PopSession() (*SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sess, err := mgr.Pop()
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, nil
	}
	info := sessionToInfo(sess)
	return &info, nil
}

func (s *Service) PeekStack() ([]SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	stack, err := mgr.Peek()
	if err != nil {
		return nil, err
	}
	var result []SessionInfo
	for i := range stack {
		result = append(result, sessionToInfo(&stack[i]))
	}
	return result, nil
}

func (s *Service) ExpireSession(uuid string) error {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	return mgr.ExpireSession(uuid)
}

// --- Graph operations ---

// GraphEdgeInfo is a transport-safe edge representation.
type GraphEdgeInfo struct {
	UUID         string  `json:"uuid"`
	SourceNodeID string  `json:"source_node_id"`
	TargetNodeID string  `json:"target_node_id"`
	EdgeType     string  `json:"edge_type"`
	Confidence   float64 `json:"confidence"`
}

// GraphPathResult holds a pathfinding result.
type GraphPathResult struct {
	Path       []GraphEdgeInfo `json:"path"`
	Hops       int             `json:"hops"`
	Confidence float64         `json:"confidence"`
}

func (s *Service) FindPath(from, to string) (*GraphPathResult, error) {
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	path, confidence, err := gs.FindPath(from, to)
	if err != nil {
		return nil, err
	}

	result := &GraphPathResult{Hops: len(path), Confidence: confidence}
	for _, e := range path {
		result.Path = append(result.Path, GraphEdgeInfo{
			UUID:         e.UUID,
			SourceNodeID: e.SourceNodeID,
			TargetNodeID: e.TargetNodeID,
			EdgeType:     string(e.EdgeType),
			Confidence:   e.Confidence,
		})
	}
	return result, nil
}

func (s *Service) GetHops(fromNodeID string) ([]GraphEdgeInfo, error) {
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	edges, err := gs.GetOutEdges(fromNodeID)
	if err != nil {
		return nil, err
	}

	var result []GraphEdgeInfo
	for _, e := range edges {
		result = append(result, GraphEdgeInfo{
			UUID:         e.UUID,
			SourceNodeID: e.SourceNodeID,
			TargetNodeID: e.TargetNodeID,
			EdgeType:     string(e.EdgeType),
			Confidence:   e.Confidence,
		})
	}
	return result, nil
}

// GraphStats holds graph statistics.
type GraphStats struct {
	Nodes      int `json:"nodes"`
	Edges      int `json:"edges"`
	StaleEdges int `json:"stale_edges"`
}

func (s *Service) GetGraphStats() (*GraphStats, error) {
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	nodes, edges, staleEdges, err := gs.Stats()
	if err != nil {
		return nil, err
	}
	return &GraphStats{
		Nodes:      nodes,
		Edges:      edges,
		StaleEdges: staleEdges,
	}, nil
}

// --- Module operations ---

// ModuleInfo is a transport-safe module metadata representation.
type ModuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	RiskClass   string   `json:"risk_class"`
	Services    []string `json:"services"`
}

func (s *Service) ListModules(keyword, service, riskClass string) []ModuleInfo {
	factory := stratusaws.NewClientFactory(s.logger)
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	reg := module.NewRegistry(s.engine.MetadataDB, s.logger)
	module.RegisterBuiltinModules(reg, factory, gs)

	var metas []ModuleInfo
	for _, m := range reg.Search(keyword, service, riskClass, "") {
		metas = append(metas, ModuleInfo{
			ID:          m.ID,
			Name:        m.Name,
			Version:     m.Version,
			Description: m.Description,
			RiskClass:   m.RiskClass,
			Services:    m.Services,
		})
	}
	return metas
}

// RunModuleRequest holds parameters for running a module.
type RunModuleRequest struct {
	ModuleID string         `json:"module_id"`
	Inputs   map[string]any `json:"inputs,omitempty"`
	DryRun   bool           `json:"dry_run"`
	Operator string         `json:"operator"`
}

// RunModuleResult holds the result of a module execution.
type RunModuleResult struct {
	RunUUID     string         `json:"run_uuid"`
	Status      string         `json:"status"`
	Outputs     map[string]any `json:"outputs,omitempty"`
	Error       string         `json:"error,omitempty"`
	Duration    string         `json:"duration,omitempty"`
	ArtifactIDs []string       `json:"artifact_ids,omitempty"`
}

func (s *Service) RunModule(ctx context.Context, req RunModuleRequest) (*RunModuleResult, error) {
	creds, sess, err := stratusaws.ResolveActiveCredentials(s.engine)
	if err != nil {
		return nil, fmt.Errorf("resolving active credentials: %w", err)
	}

	factory := stratusaws.NewClientFactoryWithAudit(s.logger, s.engine.AuditLogger, sess.UUID)
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	reg := module.NewRegistry(s.engine.MetadataDB, s.logger)
	module.RegisterBuiltinModules(reg, factory, gs)

	runner := module.NewRunner(reg, s.engine.MetadataDB, s.engine.AuditLogger, factory, gs, s.logger, s.engine.Workspace.UUID)
	runner.SetScope(scope.NewChecker(s.engine.Workspace.ScopeConfig))
	runner.SetArtifactStore(artifact.NewStore(s.engine.MetadataDB, s.engine.Workspace.Path, s.engine.Workspace.UUID))

	operator := req.Operator
	if operator == "" {
		operator = "teamserver"
	}

	cfg := module.RunConfig{
		ModuleID: req.ModuleID,
		Inputs:   req.Inputs,
		Session:  sess,
		Creds:    creds,
		DryRun:   req.DryRun,
		Operator: operator,
	}

	run, err := runner.Execute(ctx, cfg)
	if err != nil {
		return nil, err
	}

	result := &RunModuleResult{
		RunUUID:     run.UUID,
		Status:      string(run.Status),
		Outputs:     run.Outputs,
		ArtifactIDs: run.ArtifactUUIDs,
	}

	if run.CompletedAt != nil {
		result.Duration = run.CompletedAt.Sub(run.StartedAt).String()
	}
	if run.ErrorDetail != nil {
		result.Error = *run.ErrorDetail
	}

	return result, nil
}

// RunInfo is a transport-safe module run representation.
type RunInfo struct {
	UUID          string `json:"uuid"`
	ModuleID      string `json:"module_id"`
	ModuleVersion string `json:"module_version"`
	Status        string `json:"status"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at,omitempty"`
	OutputJSON    string `json:"output_json,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (s *Service) GetRunStatus(runUUID string) (*RunInfo, error) {
	factory := stratusaws.NewClientFactory(s.logger)
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	reg := module.NewRegistry(s.engine.MetadataDB, s.logger)
	module.RegisterBuiltinModules(reg, factory, gs)

	runner := module.NewRunner(reg, s.engine.MetadataDB, s.engine.AuditLogger, factory, gs, s.logger, s.engine.Workspace.UUID)
	run, err := runner.GetRun(runUUID)
	if err != nil {
		return nil, err
	}

	info := &RunInfo{
		UUID:          run.UUID,
		ModuleID:      run.ModuleID,
		ModuleVersion: run.ModuleVersion,
		Status:        string(run.Status),
		StartedAt:     run.StartedAt.Format(time.RFC3339),
	}
	if run.CompletedAt != nil {
		info.CompletedAt = run.CompletedAt.Format(time.RFC3339)
	}
	if run.Outputs != nil {
		outJSON, _ := json.Marshal(run.Outputs)
		info.OutputJSON = string(outJSON)
	}
	if run.ErrorDetail != nil {
		info.Error = *run.ErrorDetail
	}

	return info, nil
}

func (s *Service) ListRuns(moduleFilter, statusFilter string) ([]RunInfo, error) {
	factory := stratusaws.NewClientFactory(s.logger)
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	reg := module.NewRegistry(s.engine.MetadataDB, s.logger)
	module.RegisterBuiltinModules(reg, factory, gs)

	runner := module.NewRunner(reg, s.engine.MetadataDB, s.engine.AuditLogger, factory, gs, s.logger, s.engine.Workspace.UUID)
	runs, err := runner.ListRuns(moduleFilter, statusFilter)
	if err != nil {
		return nil, err
	}

	var result []RunInfo
	for _, r := range runs {
		info := RunInfo{
			UUID:          r.UUID,
			ModuleID:      r.ModuleID,
			ModuleVersion: r.ModuleVersion,
			Status:        string(r.Status),
			StartedAt:     r.StartedAt.Format(time.RFC3339),
		}
		if r.CompletedAt != nil {
			info.CompletedAt = r.CompletedAt.Format(time.RFC3339)
		}
		if r.ErrorDetail != nil {
			info.Error = *r.ErrorDetail
		}
		result = append(result, info)
	}
	return result, nil
}

// --- Audit operations ---

func (s *Service) VerifyAuditChain() (bool, int, error) {
	return audit.Verify(s.engine.AuditDB, s.engine.Workspace.UUID)
}

// suppress unused imports for packages used indirectly
var (
	_ = (*sql.DB)(nil)
)
