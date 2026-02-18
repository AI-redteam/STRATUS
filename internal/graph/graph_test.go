package graph

import (
	"testing"

	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/db"
)

func setupTestStore(t *testing.T) *Store {
	dir := t.TempDir()
	metaDB, err := db.OpenMetadataDB(dir)
	if err != nil {
		t.Fatalf("OpenMetadataDB: %v", err)
	}
	t.Cleanup(func() { metaDB.Close() })

	// Insert a workspace for FK constraint
	_, err = metaDB.Exec(
		`INSERT INTO workspaces (uuid, name, created_at, updated_at, owner, path)
		 VALUES ('test-ws', 'Test Workspace', '2025-01-01', '2025-01-01', 'local', '/tmp/test')`,
	)
	if err != nil {
		t.Fatalf("Insert workspace: %v", err)
	}

	return NewStore(metaDB, "test-ws")
}

func TestAddAndGetEdges(t *testing.T) {
	store := setupTestStore(t)

	edge := core.GraphEdge{
		SourceNodeID:            "arn:aws:iam::123:user/alice",
		TargetNodeID:            "arn:aws:iam::123:role/Admin",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "sess-1",
		Confidence:              0.95,
	}

	uuid, err := store.AddEdge(edge)
	if err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	if uuid == "" {
		t.Fatal("Expected non-empty UUID")
	}

	// Get out edges
	outEdges, err := store.GetOutEdges("arn:aws:iam::123:user/alice")
	if err != nil {
		t.Fatalf("GetOutEdges: %v", err)
	}
	if len(outEdges) != 1 {
		t.Fatalf("Expected 1 out edge, got %d", len(outEdges))
	}
	if outEdges[0].TargetNodeID != "arn:aws:iam::123:role/Admin" {
		t.Errorf("Wrong target: %s", outEdges[0].TargetNodeID)
	}

	// Get in edges
	inEdges, err := store.GetInEdges("arn:aws:iam::123:role/Admin")
	if err != nil {
		t.Fatalf("GetInEdges: %v", err)
	}
	if len(inEdges) != 1 {
		t.Fatalf("Expected 1 in edge, got %d", len(inEdges))
	}
}

func TestFindPath(t *testing.T) {
	store := setupTestStore(t)

	// Build a chain: A -> B -> C
	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "A",
		TargetNodeID:            "B",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.9,
	})
	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "B",
		TargetNodeID:            "C",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.8,
	})

	path, conf, err := store.FindPath("A", "C")
	if err != nil {
		t.Fatalf("FindPath: %v", err)
	}

	if len(path) != 2 {
		t.Fatalf("Expected 2-hop path, got %d", len(path))
	}
	if conf != 0.8 {
		t.Errorf("Expected minimum confidence 0.8, got %f", conf)
	}
}

func TestFindPathNoPath(t *testing.T) {
	store := setupTestStore(t)

	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "A",
		TargetNodeID:            "B",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.9,
	})

	_, _, err := store.FindPath("A", "Z")
	if err == nil {
		t.Fatal("Expected error for unreachable path")
	}
}

func TestHops(t *testing.T) {
	store := setupTestStore(t)

	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "user-a",
		TargetNodeID:            "role-1",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.95,
	})
	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "user-a",
		TargetNodeID:            "role-2",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.7,
	})
	// This edge is not can_assume, so should not appear in hops
	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "user-a",
		TargetNodeID:            "bucket-1",
		EdgeType:                core.EdgeCanRead,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.8,
	})

	hops, err := store.Hops("user-a")
	if err != nil {
		t.Fatalf("Hops: %v", err)
	}
	if len(hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(hops))
	}
}

func TestGraphStats(t *testing.T) {
	store := setupTestStore(t)

	store.AddNode("node-a", "iam_user", "Alice", "s1", nil)
	store.AddNode("node-b", "iam_role", "AdminRole", "s1", nil)

	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "node-a",
		TargetNodeID:            "node-b",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.9,
	})

	nodes, edges, stale, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if nodes != 2 {
		t.Errorf("Expected 2 nodes, got %d", nodes)
	}
	if edges != 1 {
		t.Errorf("Expected 1 edge, got %d", edges)
	}
	if stale != 0 {
		t.Errorf("Expected 0 stale, got %d", stale)
	}
}

func TestSnapshot(t *testing.T) {
	store := setupTestStore(t)

	store.AddNode("n1", "iam_user", "User1", "s1", nil)
	store.AddEdge(core.GraphEdge{
		SourceNodeID:            "n1",
		TargetNodeID:            "n2",
		EdgeType:                core.EdgeCanAssume,
		DiscoveredBySessionUUID: "s1",
		Confidence:              0.85,
	})

	data, err := store.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Expected non-empty snapshot")
	}
}
