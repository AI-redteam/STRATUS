// service.go implements the STRATUS API service layer.
// This is the business logic layer that both gRPC handlers and CLI can use.
package grpcapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/artifact"
	"github.com/stratus-framework/stratus/internal/audit"
	stratusaws "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/config"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/identity"
	"github.com/stratus-framework/stratus/internal/module"
	"github.com/stratus-framework/stratus/internal/scope"
	"github.com/stratus-framework/stratus/internal/session"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
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

// --- Workspace creation ---

// CreateWorkspaceRequest holds parameters for creating a new workspace.
type CreateWorkspaceRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Passphrase  string   `json:"passphrase"`
	Accounts    []string `json:"accounts"`
	Regions     []string `json:"regions"`
	Partition   string   `json:"partition"`
}

// CreateWorkspace creates a new workspace and returns an initialized engine.
// This is a standalone function that does not require an existing service/engine.
func CreateWorkspace(req CreateWorkspaceRequest) (*core.Engine, *WorkspaceInfo, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}

	scopeCfg := core.Scope{
		AccountIDs: req.Accounts,
		Regions:    req.Regions,
		Partition:  req.Partition,
	}

	engine, err := core.InitWorkspace(cfg.WorkspacesDir, req.Name, req.Description, req.Passphrase, scopeCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating workspace: %w", err)
	}

	ws := engine.Workspace
	info := &WorkspaceInfo{
		UUID:        ws.UUID,
		Name:        ws.Name,
		Description: ws.Description,
		Owner:       ws.Owner,
		CreatedAt:   ws.CreatedAt.Format(time.RFC3339),
		Path:        ws.Path,
		Accounts:    ws.ScopeConfig.AccountIDs,
		Regions:     ws.ScopeConfig.Regions,
	}
	return engine, info, nil
}

// --- Scope management ---

// UpdateScopeRequest holds parameters for updating workspace scope.
type UpdateScopeRequest struct {
	AddAccounts  []string `json:"add_accounts"`
	AddRegions   []string `json:"add_regions"`
	SetPartition string   `json:"set_partition"`
}

func (s *Service) UpdateScope(req UpdateScopeRequest) (*ScopeInfo, error) {
	sc := &s.engine.Workspace.ScopeConfig

	// Merge new accounts (deduplicated)
	if len(req.AddAccounts) > 0 {
		existing := make(map[string]bool)
		for _, a := range sc.AccountIDs {
			existing[a] = true
		}
		for _, a := range req.AddAccounts {
			if a != "" && !existing[a] {
				sc.AccountIDs = append(sc.AccountIDs, a)
				existing[a] = true
			}
		}
	}

	// Merge new regions (deduplicated)
	if len(req.AddRegions) > 0 {
		existing := make(map[string]bool)
		for _, r := range sc.Regions {
			existing[r] = true
		}
		for _, r := range req.AddRegions {
			if r != "" && !existing[r] {
				sc.Regions = append(sc.Regions, r)
				existing[r] = true
			}
		}
	}

	// Set partition if provided
	if req.SetPartition != "" {
		sc.Partition = req.SetPartition
	}

	// Persist updated workspace record
	s.engine.Workspace.UpdatedAt = time.Now().UTC()
	if err := core.SaveWorkspaceRecord(s.engine.MetadataDB, s.engine.Workspace); err != nil {
		return nil, fmt.Errorf("saving scope update: %w", err)
	}

	return s.GetScopeInfo(), nil
}

// ScopeCheckResult holds the result of a scope check.
type ScopeCheckResult struct {
	InScope bool   `json:"in_scope"`
	Reason  string `json:"reason"`
}

func (s *Service) CheckScope(region, accountID string) *ScopeCheckResult {
	checker := scope.NewChecker(s.engine.Workspace.ScopeConfig)

	if accountID != "" {
		if err := checker.CheckAccount(accountID); err != nil {
			return &ScopeCheckResult{InScope: false, Reason: err.Error()}
		}
	}
	if region != "" {
		if err := checker.CheckRegion(region); err != nil {
			return &ScopeCheckResult{InScope: false, Reason: err.Error()}
		}
	}
	return &ScopeCheckResult{InScope: true, Reason: "in scope"}
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

// --- Session intelligence ---

// WhoamiResult holds the result of a caller identity verification.
type WhoamiResult struct {
	ARN       string `json:"arn"`
	AccountID string `json:"account_id"`
	UserID    string `json:"user_id"`
	Verified  bool   `json:"verified"`
	Error     string `json:"error,omitempty"`
}

func (s *Service) SessionWhoami(uuid string) (*WhoamiResult, error) {
	creds, sess, err := stratusaws.ResolveSessionCredentials(s.engine, uuid)
	if err != nil {
		return &WhoamiResult{Error: err.Error()}, nil
	}

	factory := stratusaws.NewClientFactory(s.logger)
	arn, account, userID, stsErr := factory.GetCallerIdentity(context.Background(), creds)

	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	if stsErr != nil {
		mgr.UpdateHealth(sess.UUID, core.HealthError)
		return &WhoamiResult{Error: stsErr.Error()}, nil
	}

	mgr.UpdateHealth(sess.UUID, core.HealthHealthy)
	return &WhoamiResult{
		ARN:       arn,
		AccountID: account,
		UserID:    userID,
		Verified:  true,
	}, nil
}

// SessionHealthResult holds health status for one session.
type SessionHealthResult struct {
	UUID   string `json:"uuid"`
	Label  string `json:"label"`
	Health string `json:"health"`
	Detail string `json:"detail"`
}

func (s *Service) SessionHealthCheck() ([]SessionHealthResult, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sessions, err := mgr.ListSessions()
	if err != nil {
		return nil, err
	}

	mgr.CheckExpiry()

	var results []SessionHealthResult
	for _, sess := range sessions {
		detail := string(sess.HealthStatus)
		if sess.Expiry != nil {
			remaining := time.Until(*sess.Expiry)
			if remaining <= 0 {
				detail = "expired"
				mgr.UpdateHealth(sess.UUID, core.HealthExpired)
			} else if remaining < 15*time.Minute {
				detail = fmt.Sprintf("expiring in %dm", int(remaining.Minutes()))
			} else {
				detail = fmt.Sprintf("%dm remaining", int(remaining.Minutes()))
			}
		} else {
			detail = "long-lived key"
		}

		results = append(results, SessionHealthResult{
			UUID:   sess.UUID,
			Label:  sess.SessionName,
			Health: string(sess.HealthStatus),
			Detail: detail,
		})
	}
	return results, nil
}

func (s *Service) RefreshSession(uuid string) (*SessionInfo, error) {
	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	sess, err := mgr.GetSession(uuid)
	if err != nil {
		return nil, err
	}

	if sess.RefreshMethod == nil {
		return nil, fmt.Errorf("session %s has no refresh method", sess.UUID[:8])
	}
	if *sess.RefreshMethod != "assume_role" {
		return nil, fmt.Errorf("unsupported refresh method: %s", *sess.RefreshMethod)
	}
	if sess.ChainParentSessionUUID == nil {
		return nil, fmt.Errorf("session has no chain parent — cannot refresh")
	}

	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)
	id, err := broker.GetIdentity(sess.IdentityUUID)
	if err != nil {
		return nil, fmt.Errorf("looking up identity: %w", err)
	}

	roleARN := id.PrincipalARN
	if roleARN == "" {
		return nil, fmt.Errorf("identity has no principal ARN for role assumption")
	}

	// Retrieve external_id from vault
	externalID := ""
	raw, vaultErr := s.engine.Vault.Get(id.VaultKeyRef)
	if vaultErr == nil {
		var credMap map[string]string
		if json.Unmarshal(raw, &credMap) == nil {
			externalID = credMap["external_id"]
		}
	}

	parentCreds, parentSess, err := stratusaws.ResolveSessionCredentials(s.engine, *sess.ChainParentSessionUUID)
	if err != nil {
		return nil, fmt.Errorf("resolving parent session credentials: %w", err)
	}

	factory := stratusaws.NewClientFactoryWithAudit(s.logger, s.engine.AuditLogger, parentSess.UUID)

	sessionName := sess.SessionName
	if sessionName == "" {
		sessionName = "stratus-refresh"
	}

	result, err := factory.AssumeRole(context.Background(), parentCreds, roleARN, sessionName, externalID, 3600)
	if err != nil {
		return nil, fmt.Errorf("refreshing credentials: %w", err)
	}

	expiry := result.Expiration
	_, newSess, err := broker.ImportAssumedRoleSession(identity.AssumedRoleSessionInput{
		AccessKey:         result.AccessKeyID,
		SecretKey:         result.SecretAccessKey,
		SessionToken:      result.SessionToken,
		Expiry:            &expiry,
		Label:             sess.SessionName,
		Region:            sess.Region,
		RoleARN:           roleARN,
		ExternalID:        externalID,
		SourceSessionUUID: *sess.ChainParentSessionUUID,
	})
	if err != nil {
		return nil, fmt.Errorf("importing refreshed session: %w", err)
	}

	// Push new session if old was on stack
	stack, _ := mgr.Peek()
	for _, s := range stack {
		if s.UUID == sess.UUID {
			mgr.Push(newSess.UUID)
			break
		}
	}

	mgr.ExpireSession(sess.UUID)

	info := sessionToInfo(newSess)
	return &info, nil
}

// --- Pivot operations ---

// PivotAssumeRequest holds parameters for assuming a role.
type PivotAssumeRequest struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id"`
	Label      string `json:"label"`
	Duration   int32  `json:"duration_seconds"`
}

// PivotAssumeResult holds the result of a role assumption.
type PivotAssumeResult struct {
	Session     SessionInfo `json:"session"`
	AssumedRole string      `json:"assumed_role"`
	Expiration  string      `json:"expiration"`
}

func (s *Service) PivotAssume(req PivotAssumeRequest) (*PivotAssumeResult, error) {
	creds, sess, err := stratusaws.ResolveActiveCredentials(s.engine)
	if err != nil {
		return nil, err
	}

	// Enforce region scope only — intentional pivots to other accounts are allowed.
	// The operator is explicitly choosing to assume this role.
	checker := scope.NewChecker(s.engine.Workspace.ScopeConfig)
	if err := checker.CheckRegion(creds.Region); err != nil {
		return nil, fmt.Errorf("scope violation: %w", err)
	}

	factory := stratusaws.NewClientFactoryWithAudit(s.logger, s.engine.AuditLogger, sess.UUID)

	sessionName := "stratus"
	if req.Label != "" {
		sessionName = req.Label
	}
	duration := req.Duration
	if duration == 0 {
		duration = 3600
	}

	result, err := factory.AssumeRole(context.Background(), creds, req.RoleARN, sessionName, req.ExternalID, duration)
	if err != nil {
		return nil, err
	}

	label := req.Label
	if label == "" {
		label = result.AssumedRoleARN
	}

	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)
	expiry := result.Expiration
	_, newSess, err := broker.ImportAssumedRoleSession(identity.AssumedRoleSessionInput{
		AccessKey:         result.AccessKeyID,
		SecretKey:         result.SecretAccessKey,
		SessionToken:      result.SessionToken,
		Expiry:            &expiry,
		Label:             label,
		Region:            sess.Region,
		RoleARN:           req.RoleARN,
		ExternalID:        req.ExternalID,
		SourceSessionUUID: sess.UUID,
	})
	if err != nil {
		return nil, fmt.Errorf("importing assumed role session: %w", err)
	}

	mgr := session.NewManager(s.engine.MetadataDB, s.engine.AuditLogger, s.engine.Workspace.UUID)
	pushed, err := mgr.Push(newSess.UUID)
	if err != nil {
		return nil, fmt.Errorf("pushing session: %w", err)
	}

	return &PivotAssumeResult{
		Session:     sessionToInfo(pushed),
		AssumedRole: result.AssumedRoleARN,
		Expiration:  expiry.Format(time.RFC3339),
	}, nil
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
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	Description     string           `json:"description"`
	RiskClass       string           `json:"risk_class"`
	Services        []string         `json:"services"`
	Author          string           `json:"author"`
	Inputs          []sdk.InputSpec  `json:"inputs,omitempty"`
	Outputs         []sdk.OutputSpec `json:"outputs,omitempty"`
	References      []string         `json:"references,omitempty"`
	RequiredActions []string         `json:"required_actions,omitempty"`
}

func (s *Service) ListModules(keyword, service, riskClass string) []ModuleInfo {
	factory := stratusaws.NewClientFactory(s.logger)
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	reg := module.NewRegistry(s.engine.MetadataDB, s.logger)
	module.RegisterBuiltinModules(reg, factory, gs)

	var metas []ModuleInfo
	for _, m := range reg.Search(keyword, service, riskClass, "") {
		metas = append(metas, ModuleInfo{
			ID:              m.ID,
			Name:            m.Name,
			Version:         m.Version,
			Description:     m.Description,
			RiskClass:       m.RiskClass,
			Services:        m.Services,
			Author:          m.Author,
			Inputs:          m.Inputs,
			Outputs:         m.Outputs,
			References:      m.References,
			RequiredActions: m.RequiredActions,
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

// AuditEntry is a transport-safe audit log entry.
type AuditEntry struct {
	ID          int64  `json:"id"`
	Timestamp   string `json:"timestamp"`
	SessionUUID string `json:"session_uuid,omitempty"`
	RunUUID     string `json:"run_uuid,omitempty"`
	Operator    string `json:"operator"`
	EventType   string `json:"event_type"`
	Detail      string `json:"detail"`
	RecordHash  string `json:"record_hash"`
}

func (s *Service) ListAuditEvents(limit, offset int, eventTypeFilter string) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, session_uuid, run_uuid, operator, event_type, detail, record_hash
	          FROM audit_log WHERE workspace_uuid = ?`
	args := []any{s.engine.Workspace.UUID}

	if eventTypeFilter != "" {
		query += " AND event_type = ?"
		args = append(args, eventTypeFilter)
	}
	query += " ORDER BY id DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	rows, err := s.engine.AuditDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var sessUUID, runUUID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &sessUUID, &runUUID, &e.Operator, &e.EventType, &e.Detail, &e.RecordHash); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		if sessUUID.Valid {
			e.SessionUUID = sessUUID.String
		}
		if runUUID.Valid {
			e.RunUUID = runUUID.String
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Graph snapshot ---

func (s *Service) GetGraphSnapshot() (string, error) {
	gs := graph.NewStore(s.engine.MetadataDB, s.engine.Workspace.UUID)
	data, err := gs.Snapshot()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --- Artifact operations ---

// ArtifactInfo is a transport-safe artifact representation.
type ArtifactInfo struct {
	UUID        string `json:"uuid"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	RunUUID     string `json:"run_uuid,omitempty"`
	SessionUUID string `json:"session_uuid,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// ArtifactContent is an artifact with its content.
type ArtifactContent struct {
	ArtifactInfo
	Content string `json:"content"`
	IsText  bool   `json:"is_text"`
}

// VerifyArtifactsResult holds integrity verification results.
type VerifyArtifactsResult struct {
	Total    int  `json:"total"`
	Valid    int  `json:"valid"`
	Corrupt  int  `json:"corrupt"`
	AllValid bool `json:"all_valid"`
}

func (s *Service) ListArtifacts(runFilter, typeFilter string) ([]ArtifactInfo, error) {
	store := artifact.NewStore(s.engine.MetadataDB, s.engine.Workspace.Path, s.engine.Workspace.UUID)
	arts, err := store.List(runFilter, "")
	if err != nil {
		return nil, err
	}

	var result []ArtifactInfo
	for _, a := range arts {
		if typeFilter != "" && string(a.ArtifactType) != typeFilter {
			continue
		}
		info := ArtifactInfo{
			UUID:        a.UUID,
			Label:       a.Label,
			Type:        string(a.ArtifactType),
			SHA256:      a.ContentHash,
			SizeBytes:   a.ByteSize,
			SessionUUID: a.SessionUUID,
			CreatedAt:   a.CreatedAt.Format(time.RFC3339),
		}
		if a.RunUUID != nil {
			info.RunUUID = *a.RunUUID
		}
		result = append(result, info)
	}
	return result, nil
}

func (s *Service) GetArtifact(artUUID string) (*ArtifactContent, error) {
	store := artifact.NewStore(s.engine.MetadataDB, s.engine.Workspace.Path, s.engine.Workspace.UUID)
	art, err := store.Get(artUUID)
	if err != nil {
		return nil, err
	}

	content, err := store.ReadContent(art)
	if err != nil {
		return nil, err
	}

	info := ArtifactInfo{
		UUID:        art.UUID,
		Label:       art.Label,
		Type:        string(art.ArtifactType),
		SHA256:      art.ContentHash,
		SizeBytes:   art.ByteSize,
		SessionUUID: art.SessionUUID,
		CreatedAt:   art.CreatedAt.Format(time.RFC3339),
	}
	if art.RunUUID != nil {
		info.RunUUID = *art.RunUUID
	}

	// Detect if content is text (valid UTF-8 JSON or text)
	isText := json.Valid(content)
	if !isText {
		// Check if it's valid UTF-8 text
		isText = true
		for _, b := range content {
			if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
				isText = false
				break
			}
		}
	}

	contentStr := string(content)
	if !isText && len(content) > 4096 {
		contentStr = contentStr[:4096] + "... (truncated)"
	}

	return &ArtifactContent{
		ArtifactInfo: info,
		Content:      contentStr,
		IsText:       isText,
	}, nil
}

func (s *Service) VerifyArtifacts() (*VerifyArtifactsResult, error) {
	store := artifact.NewStore(s.engine.MetadataDB, s.engine.Workspace.Path, s.engine.Workspace.UUID)
	valid, invalid, err := store.VerifyIntegrity()
	if err != nil {
		return nil, err
	}
	total := valid + len(invalid)
	return &VerifyArtifactsResult{
		Total:    total,
		Valid:    valid,
		Corrupt:  len(invalid),
		AllValid: len(invalid) == 0,
	}, nil
}

// --- Export operations ---

// ExportRequest holds parameters for exporting a workspace.
type ExportRequest struct {
	Format string `json:"format"` // "json" or "markdown"
}

// ExportResult holds the export content.
type ExportResult struct {
	Content  string `json:"content"`
	Format   string `json:"format"`
	Filename string `json:"filename"`
}

func (s *Service) ExportWorkspace(req ExportRequest) (*ExportResult, error) {
	format := req.Format
	if format == "" {
		format = "json"
	}

	wsUUID := s.engine.Workspace.UUID
	ws := s.engine.Workspace

	// Build JSON export content
	export := map[string]any{
		"format":       "stratus_evidence_bundle_v1",
		"workspace_id": wsUUID,
		"workspace":    map[string]any{"uuid": ws.UUID, "name": ws.Name, "description": ws.Description, "created_at": ws.CreatedAt.Format(time.RFC3339)},
		"exported_at":  time.Now().UTC().Format(time.RFC3339),
	}

	// Gather identities
	idRows, _ := s.engine.MetadataDB.Query(
		"SELECT uuid, label, account_id, principal_arn, principal_type, source_type, acquired_at FROM identities WHERE workspace_uuid = ?", wsUUID)
	if idRows != nil {
		defer idRows.Close()
		var ids []map[string]string
		for idRows.Next() {
			var u, l, a, p, pt, st, at string
			idRows.Scan(&u, &l, &a, &p, &pt, &st, &at)
			ids = append(ids, map[string]string{"uuid": u, "label": l, "account_id": a, "principal_arn": p, "principal_type": pt, "source_type": st, "acquired_at": at})
		}
		export["identities"] = ids
	}

	// Gather sessions
	sessRows, _ := s.engine.MetadataDB.Query(
		"SELECT uuid, session_name, region, health_status, created_at FROM sessions WHERE workspace_uuid = ?", wsUUID)
	if sessRows != nil {
		defer sessRows.Close()
		var sess []map[string]string
		for sessRows.Next() {
			var u, n, r, h, c string
			sessRows.Scan(&u, &n, &r, &h, &c)
			sess = append(sess, map[string]string{"uuid": u, "session_name": n, "region": r, "health_status": h, "created_at": c})
		}
		export["sessions"] = sess
	}

	// Gather runs
	runRows, _ := s.engine.MetadataDB.Query(
		"SELECT uuid, module_id, status, started_at FROM module_runs WHERE workspace_uuid = ? ORDER BY started_at DESC", wsUUID)
	if runRows != nil {
		defer runRows.Close()
		var runs []map[string]string
		for runRows.Next() {
			var u, m, st, sa string
			runRows.Scan(&u, &m, &st, &sa)
			runs = append(runs, map[string]string{"uuid": u, "module_id": m, "status": st, "started_at": sa})
		}
		export["runs"] = runs
	}

	// Graph snapshot
	gs := graph.NewStore(s.engine.MetadataDB, wsUUID)
	graphData, _ := gs.Snapshot()
	if graphData != nil {
		var graphParsed any
		json.Unmarshal(graphData, &graphParsed)
		export["graph"] = graphParsed
	}

	if format == "json" {
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return nil, err
		}
		return &ExportResult{
			Content:  string(data),
			Format:   "json",
			Filename: fmt.Sprintf("stratus-export-%s.json", ws.Name),
		}, nil
	}

	// Markdown format
	var md string
	md += "# STRATUS Evidence Report\n\n"
	md += fmt.Sprintf("**Workspace:** %s (`%s`)\n\n", ws.Name, wsUUID[:8])
	md += fmt.Sprintf("**Exported:** %s\n\n---\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	data, _ := json.MarshalIndent(export, "", "  ")
	md += "## Full Export Data\n\n```json\n" + string(data) + "\n```\n"

	return &ExportResult{
		Content:  md,
		Format:   "markdown",
		Filename: fmt.Sprintf("stratus-report-%s.md", ws.Name),
	}, nil
}

// --- Scope operations ---

// ScopeInfo is a transport-safe scope representation.
type ScopeInfo struct {
	AccountIDs []string `json:"account_ids,omitempty"`
	Regions    []string `json:"regions,omitempty"`
	Partition  string   `json:"partition,omitempty"`
	OrgID      string   `json:"org_id,omitempty"`
}

func (s *Service) GetScopeInfo() *ScopeInfo {
	sc := s.engine.Workspace.ScopeConfig
	return &ScopeInfo{
		AccountIDs: sc.AccountIDs,
		Regions:    sc.Regions,
		Partition:  sc.Partition,
		OrgID:      sc.OrgID,
	}
}

// --- Note operations ---

// NoteInfo is a transport-safe note representation.
type NoteInfo struct {
	UUID        string `json:"uuid"`
	SessionUUID string `json:"session_uuid,omitempty"`
	RunUUID     string `json:"run_uuid,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	Content     string `json:"content"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	CreatedBy   string `json:"created_by"`
}

func (s *Service) ListNotes(sessionFilter, runFilter, nodeFilter string) ([]NoteInfo, error) {
	query := "SELECT uuid, content, session_uuid, run_uuid, node_id, created_at, updated_at, created_by FROM notes WHERE workspace_uuid = ?"
	args := []any{s.engine.Workspace.UUID}

	if sessionFilter != "" {
		query += " AND session_uuid = ?"
		args = append(args, sessionFilter)
	}
	if runFilter != "" {
		query += " AND run_uuid = ?"
		args = append(args, runFilter)
	}
	if nodeFilter != "" {
		query += " AND node_id = ?"
		args = append(args, nodeFilter)
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.engine.MetadataDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteInfo
	for rows.Next() {
		var n NoteInfo
		rows.Scan(&n.UUID, &n.Content, &n.SessionUUID, &n.RunUUID, &n.NodeID, &n.CreatedAt, &n.UpdatedAt, &n.CreatedBy)
		notes = append(notes, n)
	}
	return notes, nil
}

func (s *Service) GetNote(uuidOrPrefix string) (*NoteInfo, error) {
	var n NoteInfo
	err := s.engine.MetadataDB.QueryRow(
		`SELECT uuid, content, session_uuid, run_uuid, node_id, created_at, updated_at, created_by
		 FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?`,
		uuidOrPrefix, uuidOrPrefix+"%", s.engine.Workspace.UUID,
	).Scan(&n.UUID, &n.Content, &n.SessionUUID, &n.RunUUID, &n.NodeID, &n.CreatedAt, &n.UpdatedAt, &n.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("note not found: %s", uuidOrPrefix)
	}
	return &n, nil
}

// AddNoteRequest holds parameters for adding a note.
type AddNoteRequest struct {
	Content     string `json:"content"`
	SessionUUID string `json:"session_uuid,omitempty"`
	RunUUID     string `json:"run_uuid,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
}

func (s *Service) AddNote(req AddNoteRequest) (*NoteInfo, error) {
	noteUUID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.engine.MetadataDB.Exec(
		`INSERT INTO notes (uuid, workspace_uuid, session_uuid, run_uuid, node_id, content, created_at, updated_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		noteUUID, s.engine.Workspace.UUID,
		req.SessionUUID, req.RunUUID, req.NodeID,
		req.Content, now, now, "gui",
	)
	if err != nil {
		return nil, fmt.Errorf("saving note: %w", err)
	}

	return &NoteInfo{
		UUID:        noteUUID,
		SessionUUID: req.SessionUUID,
		RunUUID:     req.RunUUID,
		NodeID:      req.NodeID,
		Content:     req.Content,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   "gui",
	}, nil
}

func (s *Service) UpdateNote(uuidOrPrefix, newContent string) error {
	var fullUUID string
	err := s.engine.MetadataDB.QueryRow(
		"SELECT uuid FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?",
		uuidOrPrefix, uuidOrPrefix+"%", s.engine.Workspace.UUID,
	).Scan(&fullUUID)
	if err != nil {
		return fmt.Errorf("note not found: %s", uuidOrPrefix)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.engine.MetadataDB.Exec(
		"UPDATE notes SET content = ?, updated_at = ? WHERE uuid = ?",
		newContent, now, fullUUID,
	)
	return err
}

func (s *Service) DeleteNote(uuidOrPrefix string) error {
	var fullUUID string
	err := s.engine.MetadataDB.QueryRow(
		"SELECT uuid FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?",
		uuidOrPrefix, uuidOrPrefix+"%", s.engine.Workspace.UUID,
	).Scan(&fullUUID)
	if err != nil {
		return fmt.Errorf("note not found: %s", uuidOrPrefix)
	}

	_, err = s.engine.MetadataDB.Exec("DELETE FROM notes WHERE uuid = ?", fullUUID)
	return err
}

// --- Identity import operations ---

// ImportIAMKeyRequest holds parameters for importing an IAM key.
type ImportIAMKeyRequest struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Label     string `json:"label"`
	Region    string `json:"region"`
}

// ImportIAMKeyResult holds the result of an IAM key import.
type ImportIAMKeyResult struct {
	Identity IdentityInfo `json:"identity"`
	Session  SessionInfo  `json:"session"`
}

func (s *Service) ImportIAMKey(req ImportIAMKeyRequest) (*ImportIAMKeyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	label := req.Label
	if label == "" && len(req.AccessKey) >= 4 {
		label = "iam-key-" + req.AccessKey[len(req.AccessKey)-4:]
	}
	region := req.Region
	if region == "" {
		region = "us-east-1"
	}

	id, sess, err := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: req.AccessKey,
		SecretKey: req.SecretKey,
		Label:     label,
		Region:    region,
	})
	if err != nil {
		return nil, err
	}

	return &ImportIAMKeyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
		Session: sessionToInfo(sess),
	}, nil
}

// ImportSTSSessionRequest holds parameters for importing an STS session.
type ImportSTSSessionRequest struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token"`
	Label        string `json:"label"`
	Region       string `json:"region"`
}

func (s *Service) ImportSTSSession(req ImportSTSSessionRequest) (*ImportIAMKeyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	label := req.Label
	if label == "" && len(req.AccessKey) >= 4 {
		label = "sts-session-" + req.AccessKey[len(req.AccessKey)-4:]
	}
	region := req.Region
	if region == "" {
		region = "us-east-1"
	}

	id, sess, err := broker.ImportSTSSession(identity.STSSessionInput{
		AccessKey:    req.AccessKey,
		SecretKey:    req.SecretKey,
		SessionToken: req.SessionToken,
		Label:        label,
		Region:       region,
	})
	if err != nil {
		return nil, err
	}

	return &ImportIAMKeyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
		Session: sessionToInfo(sess),
	}, nil
}

// --- Additional identity import operations ---

// ImportIMDSRequest holds parameters for importing IMDS-captured credentials.
type ImportIMDSRequest struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token"`
	Expiry       string `json:"expiry,omitempty"` // RFC3339
	RoleName     string `json:"role_name,omitempty"`
	Label        string `json:"label"`
	Region       string `json:"region"`
}

func (s *Service) ImportIMDS(req ImportIMDSRequest) (*ImportIAMKeyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	region := req.Region
	if region == "" {
		region = "us-east-1"
	}

	var expiryTime *time.Time
	if req.Expiry != "" {
		t, err := time.Parse(time.RFC3339, req.Expiry)
		if err == nil {
			expiryTime = &t
		}
	}

	id, sess, err := broker.ImportIMDSCapture(identity.IMDSCaptureInput{
		AccessKey:    req.AccessKey,
		SecretKey:    req.SecretKey,
		SessionToken: req.SessionToken,
		Expiry:       expiryTime,
		RoleName:     req.RoleName,
		Label:        req.Label,
		Region:       region,
	})
	if err != nil {
		return nil, err
	}

	return &ImportIAMKeyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
		Session: sessionToInfo(sess),
	}, nil
}

// ImportCredProcessRequest holds parameters for importing credential_process output.
type ImportCredProcessRequest struct {
	Command      string `json:"command"`
	AccessKey    string `json:"access_key,omitempty"`
	SecretKey    string `json:"secret_key,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	Expiry       string `json:"expiry,omitempty"` // RFC3339
	Label        string `json:"label"`
	Region       string `json:"region"`
}

func (s *Service) ImportCredProcess(req ImportCredProcessRequest) (*ImportIAMKeyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	region := req.Region
	if region == "" {
		region = "us-east-1"
	}
	label := req.Label
	if label == "" {
		label = "cred-process"
	}

	var expiryTime *time.Time
	if req.Expiry != "" {
		t, err := time.Parse(time.RFC3339, req.Expiry)
		if err == nil {
			expiryTime = &t
		}
	}

	id, sess, err := broker.ImportCredProcess(identity.CredProcessInput{
		Command:      req.Command,
		AccessKey:    req.AccessKey,
		SecretKey:    req.SecretKey,
		SessionToken: req.SessionToken,
		Expiry:       expiryTime,
		Label:        label,
		Region:       region,
	})
	if err != nil {
		return nil, err
	}

	result := &ImportIAMKeyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
	}
	if sess != nil {
		result.Session = sessionToInfo(sess)
	}
	return result, nil
}

// ImportAssumeRoleRequest holds parameters for importing an assume-role identity config.
type ImportAssumeRoleRequest struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id,omitempty"`
	Label      string `json:"label"`
}

// ImportIdentityOnlyResult holds the result when only an identity is created (no session).
type ImportIdentityOnlyResult struct {
	Identity IdentityInfo `json:"identity"`
}

func (s *Service) ImportAssumeRoleIdentity(req ImportAssumeRoleRequest) (*ImportIdentityOnlyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	label := req.Label
	if label == "" {
		// Extract role name from ARN
		parts := splitARNParts(req.RoleARN)
		if len(parts) > 0 {
			label = "role-" + parts[len(parts)-1]
		} else {
			label = "assume-role"
		}
	}

	id, err := broker.ImportAssumeRole(identity.AssumeRoleInput{
		RoleARN:    req.RoleARN,
		ExternalID: req.ExternalID,
		Label:      label,
	})
	if err != nil {
		return nil, err
	}

	return &ImportIdentityOnlyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
	}, nil
}

// ImportWebIdentityRequest holds parameters for importing a web identity.
type ImportWebIdentityRequest struct {
	RoleARN  string `json:"role_arn"`
	RawToken string `json:"raw_token"`
	Label    string `json:"label"`
}

func (s *Service) ImportWebIdentity(req ImportWebIdentityRequest) (*ImportIdentityOnlyResult, error) {
	broker := identity.NewBroker(s.engine.MetadataDB, s.engine.Vault, s.engine.AuditLogger, s.engine.Workspace.UUID)

	label := req.Label
	if label == "" {
		label = "web-identity"
	}

	id, err := broker.ImportWebIdentity(identity.WebIdentityInput{
		RoleARN:  req.RoleARN,
		RawToken: req.RawToken,
		Label:    label,
	})
	if err != nil {
		return nil, err
	}

	return &ImportIdentityOnlyResult{
		Identity: IdentityInfo{
			UUID:          id.UUID,
			Label:         id.Label,
			SourceType:    string(id.SourceType),
			PrincipalARN:  id.PrincipalARN,
			PrincipalType: string(id.PrincipalType),
			AccountID:     id.AccountID,
			AcquiredAt:    id.AcquiredAt.Format(time.RFC3339),
		},
	}, nil
}

// splitARNParts splits a string by "/" for role name extraction.
func splitARNParts(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// --- AWS Explorer operations ---

// AWSExplorerRequest holds parameters for AWS service exploration.
type AWSExplorerRequest struct {
	Service string         `json:"service"` // iam, s3, ec2, lambda, secrets, ssm, cloudtrail, kms, logs
	Action  string         `json:"action"`  // users, roles, policies, buckets, instances, etc.
	Region  string         `json:"region,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
}

// AWSExplorerResult holds the result of an AWS exploration.
type AWSExplorerResult struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Data    any    `json:"data"`
	RawJSON string `json:"raw_json"`
}

func (s *Service) AWSExplore(ctx context.Context, req AWSExplorerRequest) (*AWSExplorerResult, error) {
	creds, sess, err := stratusaws.ResolveActiveCredentials(s.engine)
	if err != nil {
		return nil, err
	}

	// Override region if specified
	if req.Region != "" {
		creds.Region = req.Region
	}

	// Enforce scope
	checker := scope.NewChecker(s.engine.Workspace.ScopeConfig)
	if err := checker.CheckRegion(creds.Region); err != nil {
		return nil, fmt.Errorf("scope violation: %w", err)
	}

	factory := stratusaws.NewClientFactoryWithAudit(s.engine.Logger, s.engine.AuditLogger, sess.UUID)

	var data any
	key := req.Service + "." + req.Action

	switch key {
	// IAM
	case "iam.users":
		data, err = factory.ListIAMUsers(ctx, creds)
	case "iam.roles":
		data, err = factory.ListIAMRoles(ctx, creds)
	case "iam.policies":
		data, err = factory.ListIAMPolicies(ctx, creds, true)
	case "iam.user-detail":
		userName, _ := req.Params["user_name"].(string)
		if userName == "" {
			return nil, fmt.Errorf("user_name parameter required")
		}
		data, err = factory.GetIAMUserDetail(ctx, creds, userName)
	case "iam.role-detail":
		roleName, _ := req.Params["role_name"].(string)
		if roleName == "" {
			return nil, fmt.Errorf("role_name parameter required")
		}
		data, err = factory.GetIAMRoleDetail(ctx, creds, roleName)
	// S3
	case "s3.buckets":
		data, err = factory.ListS3Buckets(ctx, creds)
	case "s3.bucket-policy":
		bucket, _ := req.Params["bucket"].(string)
		if bucket == "" {
			return nil, fmt.Errorf("bucket parameter required")
		}
		data, err = factory.GetBucketPolicy(ctx, creds, bucket)
	// EC2
	case "ec2.instances":
		data, err = factory.ListEC2Instances(ctx, creds)
	case "ec2.security-groups":
		data, err = factory.ListSecurityGroups(ctx, creds)
	case "ec2.vpcs":
		data, err = factory.ListVPCs(ctx, creds)
	// Lambda
	case "lambda.functions":
		data, err = factory.ListLambdaFunctions(ctx, creds)
	// Secrets Manager
	case "secrets.list":
		data, err = factory.ListSecrets(ctx, creds)
	// SSM
	case "ssm.parameters":
		data, err = factory.ListSSMParameters(ctx, creds)
	// CloudTrail
	case "cloudtrail.events":
		var maxResults int32 = 50
		data, err = factory.LookupCloudTrailEvents(ctx, creds, maxResults)
	// KMS
	case "kms.keys":
		data, err = factory.ListKMSKeys(ctx, creds)
	// CloudWatch Logs
	case "logs.groups":
		prefix, _ := req.Params["prefix"].(string)
		data, err = factory.ListLogGroups(ctx, creds, prefix)
	// Regions
	case "ec2.regions":
		data, err = factory.ListRegions(ctx, creds)
	default:
		return nil, fmt.Errorf("unknown action: %s.%s", req.Service, req.Action)
	}

	if err != nil {
		return nil, err
	}

	rawJSON, _ := json.MarshalIndent(data, "", "  ")
	return &AWSExplorerResult{
		Service: req.Service,
		Action:  req.Action,
		Data:    data,
		RawJSON: string(rawJSON),
	}, nil
}

// suppress unused imports for packages used indirectly
var (
	_ = (*sql.DB)(nil)
)
