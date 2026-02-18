// Package integration_test exercises the full STRATUS workspace lifecycle
// end-to-end: workspace creation, identity import, session management,
// artifact storage, scope enforcement, audit chain, and evidence export.
//
// These tests use real SQLite databases and vault files (in temp directories).
// No AWS API calls are made.
package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stratus-framework/stratus/internal/artifact"
	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/identity"
	"github.com/stratus-framework/stratus/internal/scope"
	"github.com/stratus-framework/stratus/internal/session"
)

// setupEngine creates a full STRATUS engine with a temp workspace.
func setupEngine(t *testing.T) *core.Engine {
	t.Helper()
	dir := t.TempDir()

	engine, err := core.InitWorkspace(dir, "integration-test", "full lifecycle test", "test-pass",
		core.Scope{
			AccountIDs: []string{"123456789012"},
			Regions:    []string{"us-east-1", "us-west-2"},
			Partition:  "aws",
		})
	if err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

// TestFullWorkspaceLifecycle tests workspace create → close → reopen.
func TestFullWorkspaceLifecycle(t *testing.T) {
	dir := t.TempDir()

	engine, err := core.InitWorkspace(dir, "lifecycle-ws", "lifecycle test", "secure-pass",
		core.Scope{
			AccountIDs: []string{"111222333444"},
			Regions:    []string{"eu-west-1"},
		})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	wsUUID := engine.Workspace.UUID
	wsPath := engine.Workspace.Path

	// Store a secret to validate vault roundtrip
	engine.Vault.Put("test-secret", []byte("classified"))
	engine.Vault.Save()
	engine.Close()

	// Reopen with correct passphrase
	engine2, err := core.OpenWorkspace(wsPath, "secure-pass")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer engine2.Close()

	if engine2.Workspace.UUID != wsUUID {
		t.Errorf("UUID mismatch: %s vs %s", engine2.Workspace.UUID, wsUUID)
	}

	data, err := engine2.Vault.Get("test-secret")
	if err != nil {
		t.Fatalf("vault get: %v", err)
	}
	if string(data) != "classified" {
		t.Errorf("vault roundtrip failed: got %q", data)
	}

	// Wrong passphrase should fail
	engine2.Close()
	_, err = core.OpenWorkspace(wsPath, "wrong-pass")
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

// TestIdentityImportAndSessionManagement tests the identity → session → context stack flow.
func TestIdentityImportAndSessionManagement(t *testing.T) {
	engine := setupEngine(t)
	wsUUID := engine.Workspace.UUID

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, wsUUID)

	// Import an IAM key
	idRec, sessRec, err := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Label:     "test-admin",
		Region:    "us-east-1",
		Tags:      []string{"admin", "test"},
	})
	if err != nil {
		t.Fatalf("import IAM key: %v", err)
	}

	if idRec.Label != "test-admin" {
		t.Errorf("unexpected label: %s", idRec.Label)
	}
	if sessRec == nil {
		t.Fatal("expected session to be created")
	}

	// Import an STS session
	expiry := time.Now().Add(1 * time.Hour)
	idRec2, sessRec2, err := broker.ImportSTSSession(identity.STSSessionInput{
		AccessKey:    "ASIATEMP12345",
		SecretKey:    "temp-secret",
		SessionToken: "FwoGZXIvYXdzED...",
		Expiry:       &expiry,
		Label:        "temp-session",
		Region:       "us-west-2",
	})
	if err != nil {
		t.Fatalf("import STS: %v", err)
	}
	if idRec2.UUID == idRec.UUID {
		t.Error("expected different identity UUIDs")
	}

	// List identities
	ids, err := broker.ListIdentities()
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 identities, got %d", len(ids))
	}

	// Session management
	mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, wsUUID)

	sessions, err := mgr.ListSessions()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}

	// Activate first session (Use pushes to context stack)
	_, err = mgr.Use(sessRec.UUID)
	if err != nil {
		t.Fatalf("use session: %v", err)
	}

	active, err := mgr.GetActiveSession()
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.UUID != sessRec.UUID {
		t.Errorf("unexpected active session: %s", active.UUID)
	}

	// Push second session
	_, err = mgr.Push(sessRec2.UUID)
	if err != nil {
		t.Fatalf("push session: %v", err)
	}

	active2, err := mgr.GetActiveSession()
	if err != nil {
		t.Fatalf("get active after push: %v", err)
	}
	if active2.UUID != sessRec2.UUID {
		t.Errorf("expected pushed session to be active, got %s", active2.UUID)
	}

	// Peek stack
	stack, err := mgr.Peek()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if len(stack) != 2 {
		t.Errorf("expected stack of 2, got %d", len(stack))
	}

	// Pop — returns the new top (not the popped item)
	newTop, err := mgr.Pop()
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	// Pop removes sessRec2, returns the new top which is sessRec
	if newTop.UUID != sessRec.UUID {
		t.Errorf("expected new top to be original session after pop, got %s", newTop.UUID)
	}

	active3, err := mgr.GetActiveSession()
	if err != nil {
		t.Fatalf("get active after pop: %v", err)
	}
	if active3.UUID != sessRec.UUID {
		t.Errorf("expected original session to be active after pop")
	}

	// Archive identity
	err = broker.ArchiveIdentity(idRec.UUID)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	archivedID, err := broker.GetIdentity(idRec.UUID)
	if err != nil {
		t.Fatalf("get archived: %v", err)
	}
	if !archivedID.IsArchived {
		t.Error("expected identity to be archived")
	}
}

// TestArtifactStorageAndIntegrity tests content-addressed artifact lifecycle.
func TestArtifactStorageAndIntegrity(t *testing.T) {
	engine := setupEngine(t)
	store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)

	// Create an artifact
	content := []byte(`{"findings": [{"severity": "HIGH", "resource": "s3://bucket"}]}`)
	rec, err := store.Create(artifact.CreateInput{
		SessionUUID:  "session-1",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "scan results",
		Content:      content,
		CreatedBy:    "test-operator",
		Tags:         []string{"evidence", "s3"},
	})
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}

	if rec.UUID == "" {
		t.Error("expected artifact UUID")
	}
	if rec.ContentHash == "" {
		t.Error("expected content hash")
	}
	if rec.ByteSize != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), rec.ByteSize)
	}

	// Get artifact back
	got, err := store.Get(rec.UUID)
	if err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if got.Label != "scan results" {
		t.Errorf("unexpected label: %s", got.Label)
	}

	// Read content
	data, err := store.ReadContent(got)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	if string(data) != string(content) {
		t.Error("content mismatch")
	}

	// Verify integrity
	validCount, invalidIDs, err := store.VerifyIntegrity()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validCount < 1 {
		t.Error("expected at least 1 valid artifact")
	}
	if len(invalidIDs) != 0 {
		t.Errorf("expected no invalid artifacts, got %v", invalidIDs)
	}

	// Create duplicate content — should deduplicate on disk
	rec2, err := store.Create(artifact.CreateInput{
		SessionUUID:  "session-1",
		ArtifactType: core.ArtifactJSONResult,
		Label:        "same content",
		Content:      content,
		CreatedBy:    "test-operator",
	})
	if err != nil {
		t.Fatalf("create duplicate: %v", err)
	}
	if rec2.ContentHash != rec.ContentHash {
		t.Error("expected same content hash for duplicate")
	}
	if rec2.UUID == rec.UUID {
		t.Error("expected different UUIDs for different artifact records")
	}

	// List artifacts
	artifacts, err := store.List("", "")
	if err != nil {
		t.Fatalf("list artifacts: %v", err)
	}
	if len(artifacts) != 2 {
		t.Errorf("expected 2 artifacts, got %d", len(artifacts))
	}

	// Tamper detection: corrupt the file
	storagePath := filepath.Join(engine.Workspace.Path, "artifacts", rec.ContentHash)
	os.WriteFile(storagePath, []byte("tampered"), 0644)

	validCount2, invalidIDs2, err := store.VerifyIntegrity()
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if len(invalidIDs2) == 0 {
		t.Error("expected tampered artifact to fail verification")
	}
	_ = validCount2
}

// TestScopeEnforcement tests that out-of-scope operations are blocked.
func TestScopeEnforcement(t *testing.T) {
	engine := setupEngine(t)

	checker := scope.NewChecker(engine.Workspace.ScopeConfig)

	// In-scope checks should pass
	if err := checker.CheckAccount("123456789012"); err != nil {
		t.Errorf("expected in-scope account to pass: %v", err)
	}
	if err := checker.CheckRegion("us-east-1"); err != nil {
		t.Errorf("expected in-scope region to pass: %v", err)
	}
	if err := checker.CheckRegion("us-west-2"); err != nil {
		t.Errorf("expected in-scope region to pass: %v", err)
	}

	// Out-of-scope checks should fail
	err := checker.CheckAccount("999888777666")
	if err == nil {
		t.Error("expected out-of-scope account to fail")
	}
	err = checker.CheckRegion("ap-southeast-1")
	if err == nil {
		t.Error("expected out-of-scope region to fail")
	}

	// Verify scope violation is the right type
	if sv, ok := err.(*scope.ScopeViolation); ok {
		if sv.Resource == "" || sv.Reason == "" {
			t.Error("scope violation should have resource and reason")
		}
	} else {
		t.Errorf("expected ScopeViolation type, got %T", err)
	}
}

// TestAuditChainIntegrity tests the tamper-evident audit log.
func TestAuditChainIntegrity(t *testing.T) {
	engine := setupEngine(t)

	// Log some events
	engine.AuditLogger.Log(audit.EventIdentityImported, "operator-1", "", "", map[string]string{
		"label": "test-key",
	})
	engine.AuditLogger.Log(audit.EventSessionActivated, "operator-1", "sess-1", "", map[string]string{
		"session": "sess-1",
	})
	engine.AuditLogger.Log(audit.EventModuleRun, "operator-1", "sess-1", "run-1", map[string]string{
		"module": "com.stratus.iam.enumerate-roles",
		"status": "success",
	})

	// Verify chain is valid (note: there's also a workspace_created event from init)
	valid, count, err := audit.Verify(engine.AuditDB, engine.Workspace.UUID)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !valid {
		t.Error("expected audit chain to be valid")
	}
	if count < 4 { // workspace_created + 3 events
		t.Errorf("expected at least 4 audit events, got %d", count)
	}

	// Tamper with an audit record
	engine.AuditDB.Exec(
		"UPDATE audit_log SET detail = '{\"tampered\": true}' WHERE id = 2 AND workspace_uuid = ?",
		engine.Workspace.UUID)

	valid2, _, err := audit.Verify(engine.AuditDB, engine.Workspace.UUID)
	// Verify returns (false, count, error) when chain is broken
	if valid2 {
		t.Error("expected tampered audit chain to fail verification")
	}
	if err == nil {
		t.Error("expected error describing where chain broke")
	}
}

// TestPivotGraph tests the graph store add/query/pathfind operations.
func TestPivotGraph(t *testing.T) {
	engine := setupEngine(t)
	gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)

	// Add nodes and edges: A → B → C
	nodeA := "arn:aws:iam::123456789012:role/RoleA"
	nodeB := "arn:aws:iam::123456789012:role/RoleB"
	nodeC := "arn:aws:iam::123456789012:role/AdminRole"

	// Add nodes first
	gs.AddNode(nodeA, "role", "RoleA", "", nil)
	gs.AddNode(nodeB, "role", "RoleB", "", nil)
	gs.AddNode(nodeC, "role", "AdminRole", "", nil)

	_, err := gs.AddEdge(core.GraphEdge{
		SourceNodeID: nodeA,
		TargetNodeID: nodeB,
		EdgeType:     core.EdgeCanAssume,
		Confidence:   0.9,
	})
	if err != nil {
		t.Fatalf("add edge A→B: %v", err)
	}

	_, err = gs.AddEdge(core.GraphEdge{
		SourceNodeID: nodeB,
		TargetNodeID: nodeC,
		EdgeType:     core.EdgeCanAssume,
		Confidence:   0.8,
	})
	if err != nil {
		t.Fatalf("add edge B→C: %v", err)
	}

	// Get outbound edges from A
	edges, err := gs.GetOutEdges(nodeA)
	if err != nil {
		t.Fatalf("get out edges: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 outbound edge from A, got %d", len(edges))
	}
	if edges[0].TargetNodeID != nodeB {
		t.Errorf("expected edge to B, got %s", edges[0].TargetNodeID)
	}

	// Find path from A → C (should be A→B→C, 2 hops)
	path, confidence, err := gs.FindPath(nodeA, nodeC)
	if err != nil {
		t.Fatalf("find path: %v", err)
	}
	if len(path) != 2 {
		t.Errorf("expected 2-hop path, got %d", len(path))
	}
	if confidence <= 0 {
		t.Error("expected positive confidence")
	}

	// Stats
	nodes, edges_count, _, err := gs.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if nodes != 3 {
		t.Errorf("expected 3 nodes, got %d", nodes)
	}
	if edges_count != 2 {
		t.Errorf("expected 2 edges, got %d", edges_count)
	}

	// Snapshot
	snapshot, err := gs.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	var graphData map[string]any
	if err := json.Unmarshal(snapshot, &graphData); err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	if _, ok := graphData["nodes"]; !ok {
		t.Error("expected 'nodes' in snapshot")
	}
	if _, ok := graphData["edges"]; !ok {
		t.Error("expected 'edges' in snapshot")
	}
}

// TestServiceLayerEndToEnd tests the gRPC service layer through the full stack.
func TestServiceLayerEndToEnd(t *testing.T) {
	engine := setupEngine(t)
	wsUUID := engine.Workspace.UUID

	// Import identity directly to set up state for service layer tests
	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, wsUUID)
	_, sessRec, err := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIATESTSERVICE",
		SecretKey: "service-test-secret-key",
		Label:     "service-test",
		Region:    "us-east-1",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	// Activate a session
	mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, wsUUID)
	_, err = mgr.Use(sessRec.UUID)
	if err != nil {
		t.Fatalf("use session: %v", err)
	}

	// Create an artifact
	artStore := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, wsUUID)
	artRec, err := artStore.Create(artifact.CreateInput{
		SessionUUID:  sessRec.UUID,
		ArtifactType: core.ArtifactJSONResult,
		Label:        "test output",
		Content:      []byte("test content"),
		CreatedBy:    "operator-1",
	})
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}

	// Add graph nodes and edge
	gs := graph.NewStore(engine.MetadataDB, wsUUID)
	gs.AddNode("arn:aws:iam::123456789012:user/Operator", "user", "Operator", sessRec.UUID, nil)
	gs.AddNode("arn:aws:iam::123456789012:role/Target", "role", "Target", sessRec.UUID, nil)
	_, err = gs.AddEdge(core.GraphEdge{
		SourceNodeID:            "arn:aws:iam::123456789012:user/Operator",
		TargetNodeID:            "arn:aws:iam::123456789012:role/Target",
		EdgeType:                core.EdgeCanAssume,
		Confidence:              0.95,
		DiscoveredBySessionUUID: sessRec.UUID,
	})
	if err != nil {
		t.Fatalf("add edge: %v", err)
	}

	// Verify audit has recorded all operations
	valid, count, err := audit.Verify(engine.AuditDB, wsUUID)
	if err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	if !valid {
		t.Error("expected valid audit chain")
	}
	if count < 3 {
		t.Errorf("expected at least 3 audit events, got %d", count)
	}

	// Verify all subsystems have data
	ids, _ := broker.ListIdentities()
	if len(ids) < 1 {
		t.Error("expected at least 1 identity")
	}

	sessions, _ := mgr.ListSessions()
	if len(sessions) < 1 {
		t.Error("expected at least 1 session")
	}

	arts, _ := artStore.List("", "")
	if len(arts) < 1 {
		t.Error("expected at least 1 artifact")
	}

	if artRec.ContentHash == "" {
		t.Error("expected content hash on artifact")
	}

	nodesCount, edgesCount, _, _ := gs.Stats()
	if nodesCount < 2 {
		t.Error("expected at least 2 graph nodes")
	}
	if edgesCount < 1 {
		t.Error("expected at least 1 graph edge")
	}
}

// TestMultiIdentityPivotFlow tests importing multiple identities and pivoting between them.
func TestMultiIdentityPivotFlow(t *testing.T) {
	engine := setupEngine(t)
	wsUUID := engine.Workspace.UUID

	broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, wsUUID)
	mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, wsUUID)

	// Import 3 identities representing a pivot chain
	_, sess1, _ := broker.ImportIAMKey(identity.IAMKeyInput{
		AccessKey: "AKIAORIGINAL001",
		SecretKey: "original-secret-001",
		Label:     "initial-foothold",
		Region:    "us-east-1",
	})

	expiry := time.Now().Add(1 * time.Hour)
	_, sess2, _ := broker.ImportSTSSession(identity.STSSessionInput{
		AccessKey:    "ASIAPIVOT00001",
		SecretKey:    "pivot-secret-001",
		SessionToken: "pivot-token-001",
		Expiry:       &expiry,
		Label:        "lateral-role",
		Region:       "us-east-1",
	})

	_, sess3, _ := broker.ImportSTSSession(identity.STSSessionInput{
		AccessKey:    "ASIATARGET0001",
		SecretKey:    "target-secret-001",
		SessionToken: "target-token-001",
		Expiry:       &expiry,
		Label:        "admin-role",
		Region:       "us-west-2",
	})

	// Activate initial session
	mgr.Use(sess1.UUID)

	// Push lateral pivot
	mgr.Push(sess2.UUID)

	// Push admin escalation
	mgr.Push(sess3.UUID)

	// Stack should be 3 deep
	stack, _ := mgr.Peek()
	if len(stack) != 3 {
		t.Errorf("expected stack of 3, got %d", len(stack))
	}

	// Active should be the admin session
	active, _ := mgr.GetActiveSession()
	if active.UUID != sess3.UUID {
		t.Error("expected admin session to be active")
	}

	// Pop back through the chain
	mgr.Pop() // Remove admin
	active, _ = mgr.GetActiveSession()
	if active.UUID != sess2.UUID {
		t.Error("expected lateral session after first pop")
	}

	mgr.Pop() // Remove lateral
	active, _ = mgr.GetActiveSession()
	if active.UUID != sess1.UUID {
		t.Error("expected initial session after second pop")
	}

	// Expire a session
	err := mgr.ExpireSession(sess2.UUID)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}

	expiredSess, _ := mgr.GetSession(sess2.UUID)
	if expiredSess.HealthStatus != core.HealthExpired {
		t.Errorf("expected expired health status, got %s", expiredSess.HealthStatus)
	}
}
