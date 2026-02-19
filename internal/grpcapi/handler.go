// handler.go implements a JSON-RPC-style handler over gRPC unary calls.
// This provides a working teamserver without requiring protoc code generation.
// When proto generation is set up, these handlers can be replaced with proper
// generated service stubs that delegate to the same Service methods.
package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RPCRequest is a generic JSON-RPC-style request.
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// RPCResponse is a generic JSON-RPC-style response.
type RPCResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler dispatches JSON-RPC requests to the Service.
type Handler struct {
	service  *Service
	dispatch map[string]handlerFunc
}

type handlerFunc func(ctx context.Context, params json.RawMessage) (any, error)

// NewHandler creates a handler backed by the given service.
func NewHandler(svc *Service) *Handler {
	h := &Handler{service: svc}
	h.dispatch = map[string]handlerFunc{
		// Workspace
		"workspace.get":    h.handleGetWorkspace,
		"workspace.create": h.handleCreateWorkspace,

		// Scope
		"scope.update": h.handleUpdateScope,
		"scope.check":  h.handleCheckScope,

		// Identity
		"identity.list":    h.handleListIdentities,
		"identity.get":     h.handleGetIdentity,
		"identity.archive": h.handleArchiveIdentity,

		// Session
		"session.list":       h.handleListSessions,
		"session.active":     h.handleGetActiveSession,
		"session.activate":   h.handleActivateSession,
		"session.push":       h.handlePushSession,
		"session.pop":        h.handlePopSession,
		"session.peek":       h.handlePeekStack,
		"session.expire":     h.handleExpireSession,
		"session.whoami":     h.handleSessionWhoami,
		"session.health":    h.handleSessionHealthCheck,
		"session.refresh":   h.handleRefreshSession,
		"pivot.assume":      h.handlePivotAssume,

		// Graph
		"graph.find_path": h.handleFindPath,
		"graph.hops":      h.handleGetHops,
		"graph.stats":     h.handleGetGraphStats,

		// Module
		"module.list":       h.handleListModules,
		"module.run":        h.handleRunModule,
		"module.run_status": h.handleGetRunStatus,
		"module.list_runs":  h.handleListRuns,

		// Audit
		"audit.verify": h.handleVerifyAudit,
		"audit.list":   h.handleListAuditEvents,

		// Graph snapshot
		"graph.snapshot": h.handleGetGraphSnapshot,

		// Artifacts
		"artifact.list":   h.handleListArtifacts,
		"artifact.get":    h.handleGetArtifact,
		"artifact.verify": h.handleVerifyArtifacts,

		// Export
		"export.workspace": h.handleExportWorkspace,

		// Scope
		"scope.info": h.handleGetScopeInfo,

		// Identity import
		"identity.import_iam_key":      h.handleImportIAMKey,
		"identity.import_sts_session":  h.handleImportSTSSession,
		"identity.import_imds":         h.handleImportIMDS,
		"identity.import_cred_process": h.handleImportCredProcess,
		"identity.import_assume_role":  h.handleImportAssumeRoleIdentity,
		"identity.import_web_identity": h.handleImportWebIdentity,

		// AWS Explorer
		"aws.explore": h.handleAWSExplore,

		// Notes
		"note.list":   h.handleListNotes,
		"note.get":    h.handleGetNote,
		"note.add":    h.handleAddNote,
		"note.update": h.handleUpdateNote,
		"note.delete": h.handleDeleteNote,
	}
	return h
}

// Handle processes a JSON-RPC request and returns a response.
func (h *Handler) Handle(ctx context.Context, req *RPCRequest) *RPCResponse {
	fn, ok := h.dispatch[req.Method]
	if !ok {
		return &RPCResponse{Error: fmt.Sprintf("unknown method: %s", req.Method)}
	}

	result, err := fn(ctx, req.Params)
	if err != nil {
		return &RPCResponse{Error: err.Error()}
	}

	resultJSON, _ := json.Marshal(result)
	return &RPCResponse{Result: resultJSON}
}

// RegisterWithGRPC registers the handler as a gRPC service using a generic
// unary interceptor pattern. Clients send RPCRequest JSON and receive RPCResponse JSON.
func (h *Handler) RegisterWithGRPC(s *grpc.Server) {
	// Register a generic service descriptor for the JSON-RPC handler
	sd := grpc.ServiceDesc{
		ServiceName: "stratus.v1.StratusService",
		HandlerType: (*stratusServiceHandler)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Call",
				Handler:    h.grpcCallHandler,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
	s.RegisterService(&sd, h)
}

// stratusServiceHandler is the interface type for gRPC service registration.
type stratusServiceHandler interface{}

func (h *Handler) grpcCallHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req RPCRequest
	if err := dec(&req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	resp := h.Handle(ctx, &req)
	return resp, nil
}

// --- Handler implementations ---

func (h *Handler) handleGetWorkspace(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.GetWorkspace(), nil
}

func (h *Handler) handleListIdentities(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.ListIdentities()
}

type uuidParam struct {
	UUID string `json:"uuid"`
}

func (h *Handler) handleGetIdentity(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.GetIdentity(p.UUID)
}

func (h *Handler) handleArchiveIdentity(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, h.service.ArchiveIdentity(p.UUID)
}

func (h *Handler) handleListSessions(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.ListSessions()
}

func (h *Handler) handleGetActiveSession(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.GetActiveSession()
}

func (h *Handler) handleActivateSession(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ActivateSession(p.UUID)
}

func (h *Handler) handlePushSession(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.PushSession(p.UUID)
}

func (h *Handler) handlePopSession(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.PopSession()
}

func (h *Handler) handlePeekStack(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.PeekStack()
}

func (h *Handler) handleExpireSession(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, h.service.ExpireSession(p.UUID)
}

type pathParams struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (h *Handler) handleFindPath(_ context.Context, params json.RawMessage) (any, error) {
	var p pathParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.FindPath(p.From, p.To)
}

type nodeParam struct {
	NodeID string `json:"node_id"`
}

func (h *Handler) handleGetHops(_ context.Context, params json.RawMessage) (any, error) {
	var p nodeParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.GetHops(p.NodeID)
}

func (h *Handler) handleGetGraphStats(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.GetGraphStats()
}

type moduleSearchParams struct {
	Keyword   string `json:"keyword"`
	Service   string `json:"service"`
	RiskClass string `json:"risk_class"`
}

func (h *Handler) handleListModules(_ context.Context, params json.RawMessage) (any, error) {
	var p moduleSearchParams
	if params != nil {
		json.Unmarshal(params, &p)
	}
	return h.service.ListModules(p.Keyword, p.Service, p.RiskClass), nil
}

func (h *Handler) handleRunModule(ctx context.Context, params json.RawMessage) (any, error) {
	var req RunModuleRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.RunModule(ctx, req)
}

type runFilterParams struct {
	RunUUID  string `json:"run_uuid"`
	Module   string `json:"module"`
	Status   string `json:"status"`
}

func (h *Handler) handleGetRunStatus(_ context.Context, params json.RawMessage) (any, error) {
	var p runFilterParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.GetRunStatus(p.RunUUID)
}

func (h *Handler) handleListRuns(_ context.Context, params json.RawMessage) (any, error) {
	var p runFilterParams
	if params != nil {
		json.Unmarshal(params, &p)
	}
	return h.service.ListRuns(p.Module, p.Status)
}

func (h *Handler) handleVerifyAudit(_ context.Context, _ json.RawMessage) (any, error) {
	valid, count, err := h.service.VerifyAuditChain()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"valid": valid,
		"count": count,
	}, nil
}

type auditListParams struct {
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
	EventType string `json:"event_type"`
}

func (h *Handler) handleListAuditEvents(_ context.Context, params json.RawMessage) (any, error) {
	var p auditListParams
	if params != nil {
		json.Unmarshal(params, &p)
	}
	return h.service.ListAuditEvents(p.Limit, p.Offset, p.EventType)
}

func (h *Handler) handleGetGraphSnapshot(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.GetGraphSnapshot()
}

func (h *Handler) handleGetScopeInfo(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.GetScopeInfo(), nil
}

type noteFilterParams struct {
	Session string `json:"session"`
	Run     string `json:"run"`
	Node    string `json:"node"`
}

func (h *Handler) handleListNotes(_ context.Context, params json.RawMessage) (any, error) {
	var p noteFilterParams
	if params != nil {
		json.Unmarshal(params, &p)
	}
	return h.service.ListNotes(p.Session, p.Run, p.Node)
}

func (h *Handler) handleGetNote(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.GetNote(p.UUID)
}

func (h *Handler) handleAddNote(_ context.Context, params json.RawMessage) (any, error) {
	var req AddNoteRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.AddNote(req)
}

type noteUpdateParams struct {
	UUID    string `json:"uuid"`
	Content string `json:"content"`
}

func (h *Handler) handleUpdateNote(_ context.Context, params json.RawMessage) (any, error) {
	var p noteUpdateParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, h.service.UpdateNote(p.UUID, p.Content)
}

func (h *Handler) handleImportIAMKey(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportIAMKeyRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportIAMKey(req)
}

func (h *Handler) handleImportSTSSession(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportSTSSessionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportSTSSession(req)
}

func (h *Handler) handleDeleteNote(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, h.service.DeleteNote(p.UUID)
}

func (h *Handler) handleCreateWorkspace(_ context.Context, params json.RawMessage) (any, error) {
	var req CreateWorkspaceRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	_, info, err := CreateWorkspace(req)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (h *Handler) handleUpdateScope(_ context.Context, params json.RawMessage) (any, error) {
	var req UpdateScopeRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.UpdateScope(req)
}

type scopeCheckParams struct {
	Region    string `json:"region"`
	AccountID string `json:"account_id"`
}

func (h *Handler) handleCheckScope(_ context.Context, params json.RawMessage) (any, error) {
	var p scopeCheckParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.CheckScope(p.Region, p.AccountID), nil
}

type artifactFilterParams struct {
	RunUUID    string `json:"run_uuid"`
	TypeFilter string `json:"type_filter"`
}

func (h *Handler) handleListArtifacts(_ context.Context, params json.RawMessage) (any, error) {
	var p artifactFilterParams
	if params != nil {
		json.Unmarshal(params, &p)
	}
	return h.service.ListArtifacts(p.RunUUID, p.TypeFilter)
}

func (h *Handler) handleGetArtifact(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.GetArtifact(p.UUID)
}

func (h *Handler) handleVerifyArtifacts(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.VerifyArtifacts()
}

func (h *Handler) handleExportWorkspace(_ context.Context, params json.RawMessage) (any, error) {
	var req ExportRequest
	if params != nil {
		json.Unmarshal(params, &req)
	}
	return h.service.ExportWorkspace(req)
}

func (h *Handler) handleSessionWhoami(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.SessionWhoami(p.UUID)
}

func (h *Handler) handleSessionHealthCheck(_ context.Context, _ json.RawMessage) (any, error) {
	return h.service.SessionHealthCheck()
}

func (h *Handler) handleRefreshSession(_ context.Context, params json.RawMessage) (any, error) {
	var p uuidParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.RefreshSession(p.UUID)
}

func (h *Handler) handlePivotAssume(_ context.Context, params json.RawMessage) (any, error) {
	var req PivotAssumeRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.PivotAssume(req)
}

func (h *Handler) handleAWSExplore(ctx context.Context, params json.RawMessage) (any, error) {
	var req AWSExplorerRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.AWSExplore(ctx, req)
}

func (h *Handler) handleImportIMDS(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportIMDSRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportIMDS(req)
}

func (h *Handler) handleImportCredProcess(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportCredProcessRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportCredProcess(req)
}

func (h *Handler) handleImportAssumeRoleIdentity(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportAssumeRoleRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportAssumeRoleIdentity(req)
}

func (h *Handler) handleImportWebIdentity(_ context.Context, params json.RawMessage) (any, error) {
	var req ImportWebIdentityRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return h.service.ImportWebIdentity(req)
}
