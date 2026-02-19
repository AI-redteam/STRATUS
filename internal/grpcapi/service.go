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

// suppress unused imports for packages used indirectly
var (
	_ = (*sql.DB)(nil)
)
