// Package graph implements the SQLite-backed pivot graph with BFS/Dijkstra path finding.
package graph

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stratus-framework/stratus/internal/core"
)

// Store provides graph read/write operations backed by SQLite.
type Store struct {
	db            *sql.DB
	workspaceUUID string
}

// NewStore creates a graph store for the given workspace.
func NewStore(db *sql.DB, workspaceUUID string) *Store {
	return &Store{db: db, workspaceUUID: workspaceUUID}
}

// AddEdge inserts a new graph edge. If an edge between the same source/target
// with the same type already exists, the existing edge is updated.
func (s *Store) AddEdge(edge core.GraphEdge) (string, error) {
	if edge.UUID == "" {
		edge.UUID = uuid.New().String()
	}
	if edge.WorkspaceUUID == "" {
		edge.WorkspaceUUID = s.workspaceUUID
	}
	if edge.DiscoveredAt.IsZero() {
		edge.DiscoveredAt = time.Now().UTC()
	}

	evidenceJSON, _ := json.Marshal(edge.EvidenceRefs)
	apiCallsJSON, _ := json.Marshal(edge.APICallsUsed)
	constraintsJSON, _ := json.Marshal(edge.Constraints)

	// Check for existing edge
	var existingUUID string
	err := s.db.QueryRow(
		`SELECT uuid FROM graph_edges
		 WHERE workspace_uuid = ? AND source_node_id = ? AND target_node_id = ? AND edge_type = ?`,
		s.workspaceUUID, edge.SourceNodeID, edge.TargetNodeID, string(edge.EdgeType),
	).Scan(&existingUUID)

	if err == nil {
		// Update existing edge
		_, err = s.db.Exec(
			`UPDATE graph_edges SET confidence = ?, evidence_refs = ?, api_calls_used = ?,
			 constraints = ?, is_stale = 0, discovered_at = ?, discovered_by_session_uuid = ?
			 WHERE uuid = ?`,
			edge.Confidence, string(evidenceJSON), string(apiCallsJSON),
			string(constraintsJSON), edge.DiscoveredAt.Format(time.RFC3339),
			edge.DiscoveredBySessionUUID, existingUUID,
		)
		return existingUUID, err
	}

	// Insert new edge
	_, err = s.db.Exec(
		`INSERT INTO graph_edges (uuid, workspace_uuid, source_node_id, target_node_id, edge_type,
		 evidence_refs, api_calls_used, discovered_by_session_uuid, discovered_at, confidence,
		 constraints, is_stale)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		edge.UUID, s.workspaceUUID, edge.SourceNodeID, edge.TargetNodeID,
		string(edge.EdgeType), string(evidenceJSON), string(apiCallsJSON),
		edge.DiscoveredBySessionUUID, edge.DiscoveredAt.Format(time.RFC3339),
		edge.Confidence, string(constraintsJSON),
	)
	return edge.UUID, err
}

// AddNode inserts or updates a graph node.
func (s *Store) AddNode(id, nodeType, label, sessionUUID string, metadata map[string]any) error {
	metadataJSON, _ := json.Marshal(metadata)
	now := time.Now().UTC()

	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO graph_nodes (id, workspace_uuid, node_type, label, metadata, discovered_at, discovered_by_session_uuid, is_stale)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, s.workspaceUUID, nodeType, label, string(metadataJSON),
		now.Format(time.RFC3339), sessionUUID,
	)
	return err
}

// GetOutEdges returns all edges originating from the given node.
func (s *Store) GetOutEdges(sourceNodeID string) ([]core.GraphEdge, error) {
	rows, err := s.db.Query(
		`SELECT uuid, workspace_uuid, source_node_id, target_node_id, edge_type,
		        evidence_refs, api_calls_used, discovered_by_session_uuid, discovered_at,
		        confidence, constraints, is_stale
		 FROM graph_edges WHERE workspace_uuid = ? AND source_node_id = ?`,
		s.workspaceUUID, sourceNodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEdges(rows)
}

// GetInEdges returns all edges targeting the given node.
func (s *Store) GetInEdges(targetNodeID string) ([]core.GraphEdge, error) {
	rows, err := s.db.Query(
		`SELECT uuid, workspace_uuid, source_node_id, target_node_id, edge_type,
		        evidence_refs, api_calls_used, discovered_by_session_uuid, discovered_at,
		        confidence, constraints, is_stale
		 FROM graph_edges WHERE workspace_uuid = ? AND target_node_id = ?`,
		s.workspaceUUID, targetNodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEdges(rows)
}

// AllEdges returns all edges in the workspace graph.
func (s *Store) AllEdges() ([]core.GraphEdge, error) {
	rows, err := s.db.Query(
		`SELECT uuid, workspace_uuid, source_node_id, target_node_id, edge_type,
		        evidence_refs, api_calls_used, discovered_by_session_uuid, discovered_at,
		        confidence, constraints, is_stale
		 FROM graph_edges WHERE workspace_uuid = ?`,
		s.workspaceUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEdges(rows)
}

// FindPath uses BFS to find the shortest path between source and target nodes.
// Returns the list of edges forming the path.
func (s *Store) FindPath(sourceNodeID, targetNodeID string) ([]core.GraphEdge, float64, error) {
	// Build adjacency list from database
	edges, err := s.AllEdges()
	if err != nil {
		return nil, 0, err
	}

	adj := make(map[string][]core.GraphEdge)
	for _, e := range edges {
		adj[e.SourceNodeID] = append(adj[e.SourceNodeID], e)
	}

	// BFS
	type queueItem struct {
		nodeID string
		path   []core.GraphEdge
		conf   float64 // Minimum confidence along path
	}

	visited := make(map[string]bool)
	queue := []queueItem{{nodeID: sourceNodeID, path: nil, conf: 1.0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.nodeID == targetNodeID {
			return current.path, current.conf, nil
		}

		if visited[current.nodeID] {
			continue
		}
		visited[current.nodeID] = true

		for _, edge := range adj[current.nodeID] {
			if !visited[edge.TargetNodeID] {
				newPath := make([]core.GraphEdge, len(current.path)+1)
				copy(newPath, current.path)
				newPath[len(current.path)] = edge

				newConf := current.conf
				if edge.Confidence < newConf {
					newConf = edge.Confidence
				}

				queue = append(queue, queueItem{
					nodeID: edge.TargetNodeID,
					path:   newPath,
					conf:   newConf,
				})
			}
		}
	}

	return nil, 0, fmt.Errorf("no path found from %s to %s", sourceNodeID, targetNodeID)
}

// Hops returns all nodes directly reachable from the given source via can_assume edges.
func (s *Store) Hops(sourceNodeID string) ([]core.GraphEdge, error) {
	rows, err := s.db.Query(
		`SELECT uuid, workspace_uuid, source_node_id, target_node_id, edge_type,
		        evidence_refs, api_calls_used, discovered_by_session_uuid, discovered_at,
		        confidence, constraints, is_stale
		 FROM graph_edges WHERE workspace_uuid = ? AND source_node_id = ? AND edge_type = 'can_assume'`,
		s.workspaceUUID, sourceNodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEdges(rows)
}

// MarkStale marks all edges older than the given threshold as stale.
func (s *Store) MarkStale(threshold time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-threshold)
	result, err := s.db.Exec(
		"UPDATE graph_edges SET is_stale = 1 WHERE workspace_uuid = ? AND discovered_at < ? AND is_stale = 0",
		s.workspaceUUID, cutoff.Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Stats returns graph statistics: node count, edge count, stale edge count.
func (s *Store) Stats() (nodes int, edges int, staleEdges int, err error) {
	s.db.QueryRow("SELECT COUNT(*) FROM graph_nodes WHERE workspace_uuid = ?", s.workspaceUUID).Scan(&nodes)
	s.db.QueryRow("SELECT COUNT(*) FROM graph_edges WHERE workspace_uuid = ?", s.workspaceUUID).Scan(&edges)
	s.db.QueryRow("SELECT COUNT(*) FROM graph_edges WHERE workspace_uuid = ? AND is_stale = 1", s.workspaceUUID).Scan(&staleEdges)
	return
}

// Snapshot exports the complete graph state as JSON.
func (s *Store) Snapshot() ([]byte, error) {
	edges, err := s.AllEdges()
	if err != nil {
		return nil, err
	}

	// Get all nodes
	nodeRows, err := s.db.Query(
		"SELECT id, node_type, label, metadata FROM graph_nodes WHERE workspace_uuid = ?",
		s.workspaceUUID,
	)
	if err != nil {
		return nil, err
	}
	defer nodeRows.Close()

	type nodeInfo struct {
		ID       string         `json:"id"`
		Type     string         `json:"type"`
		Label    string         `json:"label"`
		Metadata map[string]any `json:"metadata,omitempty"`
	}

	var nodes []nodeInfo
	for nodeRows.Next() {
		var n nodeInfo
		var metadataJSON string
		nodeRows.Scan(&n.ID, &n.Type, &n.Label, &metadataJSON)
		json.Unmarshal([]byte(metadataJSON), &n.Metadata)
		nodes = append(nodes, n)
	}

	snapshot := map[string]any{
		"workspace_uuid": s.workspaceUUID,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"nodes":          nodes,
		"edges":          edges,
	}

	return json.MarshalIndent(snapshot, "", "  ")
}

func scanEdges(rows *sql.Rows) ([]core.GraphEdge, error) {
	var edges []core.GraphEdge
	for rows.Next() {
		var e core.GraphEdge
		var evidenceJSON, apiCallsJSON, constraintsJSON, discoveredAt string
		var isStale int

		err := rows.Scan(
			&e.UUID, &e.WorkspaceUUID, &e.SourceNodeID, &e.TargetNodeID,
			&e.EdgeType, &evidenceJSON, &apiCallsJSON,
			&e.DiscoveredBySessionUUID, &discoveredAt,
			&e.Confidence, &constraintsJSON, &isStale,
		)
		if err != nil {
			return nil, err
		}

		e.DiscoveredAt, _ = time.Parse(time.RFC3339, discoveredAt)
		json.Unmarshal([]byte(evidenceJSON), &e.EvidenceRefs)
		json.Unmarshal([]byte(apiCallsJSON), &e.APICallsUsed)
		json.Unmarshal([]byte(constraintsJSON), &e.Constraints)
		e.IsStale = isStale != 0

		edges = append(edges, e)
	}
	return edges, nil
}
