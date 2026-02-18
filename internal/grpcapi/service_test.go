package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/identity"
)

func setupTestEngine(t *testing.T) *core.Engine {
	t.Helper()
	dir := t.TempDir()

	engine, err := core.InitWorkspace(dir, "svc-test", "service test", "test-pass",
		core.Scope{
			AccountIDs: []string{"123456789012"},
			Regions:    []string{"us-east-1", "us-west-2"},
		})
	if err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	return engine
}

func TestServiceGetWorkspace(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	ws := svc.GetWorkspace()

	if ws.Name != "svc-test" {
		t.Errorf("expected name 'svc-test', got %q", ws.Name)
	}
	if ws.Description != "service test" {
		t.Errorf("expected description, got %q", ws.Description)
	}
	if len(ws.Accounts) != 1 || ws.Accounts[0] != "123456789012" {
		t.Error("scope accounts not returned")
	}
	if len(ws.Regions) != 2 {
		t.Error("scope regions not returned")
	}
}

func TestServiceListIdentities(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
	broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIA1", SecretKey: "s1", Label: "key-one",
	})
	broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIA2", SecretKey: "s2", Label: "key-two",
	})

	svc := NewService(engine)
	ids, err := svc.ListIdentities()
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 identities, got %d", len(ids))
	}
}

func TestServiceGetIdentity(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
	created, _, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIATEST", SecretKey: "secret", Label: "get-test",
	})

	svc := NewService(engine)

	// By UUID
	got, err := svc.GetIdentity(created.UUID)
	if err != nil {
		t.Fatalf("get by UUID: %v", err)
	}
	if got.Label != "get-test" {
		t.Errorf("expected 'get-test', got %q", got.Label)
	}

	// By label
	got, err = svc.GetIdentity("get-test")
	if err != nil {
		t.Fatalf("get by label: %v", err)
	}
	if got.UUID != created.UUID {
		t.Error("get by label returned wrong identity")
	}
}

func TestServiceArchiveIdentity(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
	created, _, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIATEST", SecretKey: "secret", Label: "archive-me",
	})

	svc := NewService(engine)

	if err := svc.ArchiveIdentity(created.UUID); err != nil {
		t.Fatalf("archive: %v", err)
	}

	ids, _ := svc.ListIdentities()
	if len(ids) != 0 {
		t.Errorf("expected 0 identities after archive, got %d", len(ids))
	}
}

func TestServiceSessionOperations(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
	_, sess1, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIA1", SecretKey: "s1", Label: "key1",
	})
	_, sess2, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIA2", SecretKey: "s2", Label: "key2",
	})

	svc := NewService(engine)

	// List sessions
	sessions, err := svc.ListSessions()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}

	// Activate session
	activated, err := svc.ActivateSession(sess1.UUID)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if activated.UUID != sess1.UUID {
		t.Error("wrong session activated")
	}

	// Push/pop
	pushed, err := svc.PushSession(sess2.UUID)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if pushed.UUID != sess2.UUID {
		t.Error("wrong session pushed")
	}

	// Peek stack — should have 2 entries (Use=Push + Push)
	stack, err := svc.PeekStack()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if len(stack) != 2 {
		t.Errorf("expected stack of 2, got %d", len(stack))
	}

	// Pop
	_, err = svc.PopSession()
	if err != nil {
		t.Fatalf("pop: %v", err)
	}

	// Expire
	err = svc.ExpireSession(sess1.UUID)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
}

func TestServiceGraphStats(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	stats, err := svc.GetGraphStats()
	if err != nil {
		t.Fatalf("graph stats: %v", err)
	}
	if stats.Nodes != 0 || stats.Edges != 0 {
		t.Errorf("expected empty graph, got nodes=%d edges=%d", stats.Nodes, stats.Edges)
	}
}

func TestServiceListModules(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	mods := svc.ListModules("", "", "")
	if len(mods) == 0 {
		t.Error("expected at least one builtin module")
	}

	// Search by service
	iamMods := svc.ListModules("", "IAM", "")
	if len(iamMods) == 0 {
		t.Error("expected IAM modules")
	}

	// Search by keyword
	enumMods := svc.ListModules("enumerate", "", "")
	if len(enumMods) == 0 {
		t.Error("expected enumerate modules")
	}
}

func TestServiceVerifyAuditChain(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	valid, count, err := svc.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("expected valid audit chain")
	}
	// InitWorkspace logs workspace_created event
	if count < 1 {
		t.Errorf("expected at least 1 audit record, got %d", count)
	}
}

// --- Handler (JSON-RPC dispatch) tests ---

func TestHandlerGetWorkspace(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	handler := NewHandler(svc)

	resp := handler.Handle(context.Background(), &RPCRequest{Method: "workspace.get"})
	if resp.Error != "" {
		t.Fatalf("handler error: %s", resp.Error)
	}

	var ws WorkspaceInfo
	json.Unmarshal(resp.Result, &ws)
	if ws.Name != "svc-test" {
		t.Errorf("expected 'svc-test', got %q", ws.Name)
	}
}

func TestHandlerUnknownMethod(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	handler := NewHandler(svc)

	resp := handler.Handle(context.Background(), &RPCRequest{Method: "nonexistent.method"})
	if resp.Error == "" {
		t.Error("expected error for unknown method")
	}
}

func TestHandlerListModules(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	handler := NewHandler(svc)

	resp := handler.Handle(context.Background(), &RPCRequest{Method: "module.list"})
	if resp.Error != "" {
		t.Fatalf("handler error: %s", resp.Error)
	}

	var mods []ModuleInfo
	json.Unmarshal(resp.Result, &mods)
	if len(mods) == 0 {
		t.Error("expected modules in response")
	}
}

func TestHandlerVerifyAudit(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	handler := NewHandler(svc)

	resp := handler.Handle(context.Background(), &RPCRequest{Method: "audit.verify"})
	if resp.Error != "" {
		t.Fatalf("handler error: %s", resp.Error)
	}

	var result map[string]any
	json.Unmarshal(resp.Result, &result)
	if result["valid"] != true {
		t.Error("expected valid audit chain")
	}
}

func TestHandlerSessionFlow(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	// Import a key to get a session
	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
	_, sess, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIATEST", SecretKey: "secret", Label: "handler-test",
	})

	svc := NewService(engine)
	handler := NewHandler(svc)

	// List sessions
	resp := handler.Handle(context.Background(), &RPCRequest{Method: "session.list"})
	if resp.Error != "" {
		t.Fatalf("list error: %s", resp.Error)
	}

	// Activate session
	params, _ := json.Marshal(uuidParam{UUID: sess.UUID})
	resp = handler.Handle(context.Background(), &RPCRequest{Method: "session.activate", Params: params})
	if resp.Error != "" {
		t.Fatalf("activate error: %s", resp.Error)
	}

	// Get active
	resp = handler.Handle(context.Background(), &RPCRequest{Method: "session.active"})
	if resp.Error != "" {
		t.Fatalf("get active error: %s", resp.Error)
	}

	var active SessionInfo
	json.Unmarshal(resp.Result, &active)
	if active.UUID != sess.UUID {
		t.Errorf("expected active session %s, got %s", sess.UUID, active.UUID)
	}
}

func TestHandlerGraphStats(t *testing.T) {
	engine := setupTestEngine(t)
	defer engine.Close()

	svc := NewService(engine)
	handler := NewHandler(svc)

	resp := handler.Handle(context.Background(), &RPCRequest{Method: "graph.stats"})
	if resp.Error != "" {
		t.Fatalf("handler error: %s", resp.Error)
	}

	var stats GraphStats
	json.Unmarshal(resp.Result, &stats)
	if stats.Nodes != 0 {
		t.Errorf("expected 0 nodes, got %d", stats.Nodes)
	}
}
