// Package artifact implements content-addressed artifact storage for STRATUS.
// Artifacts are persisted as flat files under the workspace artifacts/ directory,
// named by their SHA-256 content hash, with metadata tracked in SQLite.
package artifact

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/stratus-framework/stratus/internal/core"
)

// Store manages artifact persistence (files on disk + metadata in SQLite).
type Store struct {
	db           *sql.DB
	artifactsDir string // Absolute path to workspace artifacts/ directory
	workspace    string // Workspace UUID
}

// NewStore creates an artifact store for the given workspace.
func NewStore(db *sql.DB, workspacePath, workspaceUUID string) *Store {
	return &Store{
		db:           db,
		artifactsDir: filepath.Join(workspacePath, "artifacts"),
		workspace:    workspaceUUID,
	}
}

// CreateInput holds parameters for creating an artifact.
type CreateInput struct {
	RunUUID      *string
	SessionUUID  string
	ArtifactType core.ArtifactType
	Label        string
	Content      []byte
	CreatedBy    string
	Tags         []string
	IsSensitive  bool
}

// Create stores artifact content on disk and records metadata in the database.
// The file is named by its SHA-256 hash (content-addressed), so duplicate content
// is deduplicated on disk automatically.
func (s *Store) Create(input CreateInput) (*core.ArtifactRecord, error) {
	// Compute content hash
	h := sha256.Sum256(input.Content)
	contentHash := hex.EncodeToString(h[:])

	// Write content to disk (content-addressed filename)
	storageName := contentHash
	storagePath := filepath.Join(s.artifactsDir, storageName)

	if err := os.MkdirAll(s.artifactsDir, 0700); err != nil {
		return nil, fmt.Errorf("ensuring artifacts directory: %w", err)
	}

	// Only write if not already present (dedup)
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		if err := os.WriteFile(storagePath, input.Content, 0600); err != nil {
			return nil, fmt.Errorf("writing artifact file: %w", err)
		}
	}

	artUUID := uuid.New().String()
	now := time.Now().UTC()

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, _ := json.Marshal(tags)

	isSensitive := 0
	if input.IsSensitive {
		isSensitive = 1
	}

	_, err := s.db.Exec(
		`INSERT INTO artifacts (uuid, workspace_uuid, run_uuid, session_uuid, artifact_type, label,
		 content_hash, storage_path, byte_size, created_at, created_by, linked_node_ids, tags, is_sensitive)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)`,
		artUUID, s.workspace, input.RunUUID, input.SessionUUID,
		string(input.ArtifactType), input.Label,
		contentHash, storageName, len(input.Content),
		now.Format(time.RFC3339), input.CreatedBy,
		string(tagsJSON), isSensitive,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting artifact record: %w", err)
	}

	return &core.ArtifactRecord{
		UUID:         artUUID,
		WorkspaceUUID: s.workspace,
		RunUUID:      input.RunUUID,
		SessionUUID:  input.SessionUUID,
		ArtifactType: input.ArtifactType,
		Label:        input.Label,
		ContentHash:  contentHash,
		StoragePath:  storageName,
		ByteSize:     int64(len(input.Content)),
		CreatedAt:    now,
		CreatedBy:    input.CreatedBy,
		Tags:         tags,
		IsSensitive:  input.IsSensitive,
	}, nil
}

// CreateFromReader stores artifact content from a reader.
func (s *Store) CreateFromReader(input CreateInput, r io.Reader) (*core.ArtifactRecord, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading artifact content: %w", err)
	}
	input.Content = content
	return s.Create(input)
}

// Get retrieves an artifact record by UUID (supports prefix match).
func (s *Store) Get(artUUID string) (*core.ArtifactRecord, error) {
	var art core.ArtifactRecord
	var tagsJSON, createdAt string
	var runUUID sql.NullString
	var isSensitive int

	err := s.db.QueryRow(
		`SELECT uuid, workspace_uuid, run_uuid, session_uuid, artifact_type, label,
		 content_hash, storage_path, byte_size, created_at, created_by, tags, is_sensitive
		 FROM artifacts WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?`,
		artUUID, artUUID+"%", s.workspace,
	).Scan(
		&art.UUID, &art.WorkspaceUUID, &runUUID, &art.SessionUUID,
		&art.ArtifactType, &art.Label,
		&art.ContentHash, &art.StoragePath, &art.ByteSize,
		&createdAt, &art.CreatedBy, &tagsJSON, &isSensitive,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("artifact not found: %s", artUUID)
		}
		return nil, err
	}

	art.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if runUUID.Valid {
		art.RunUUID = &runUUID.String
	}
	json.Unmarshal([]byte(tagsJSON), &art.Tags)
	art.IsSensitive = isSensitive != 0

	return &art, nil
}

// ReadContent returns the raw bytes of an artifact.
func (s *Store) ReadContent(art *core.ArtifactRecord) ([]byte, error) {
	path := filepath.Join(s.artifactsDir, art.StoragePath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading artifact file: %w", err)
	}

	// Verify integrity
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != art.ContentHash {
		return nil, fmt.Errorf("artifact integrity check failed: hash mismatch for %s", art.UUID)
	}

	return data, nil
}

// List returns artifacts matching the given filters.
func (s *Store) List(runUUID, sessionUUID string) ([]core.ArtifactRecord, error) {
	query := `SELECT uuid, workspace_uuid, run_uuid, session_uuid, artifact_type, label,
	           content_hash, storage_path, byte_size, created_at, created_by, tags, is_sensitive
	           FROM artifacts WHERE workspace_uuid = ?`
	args := []any{s.workspace}

	if runUUID != "" {
		query += " AND run_uuid = ?"
		args = append(args, runUUID)
	}
	if sessionUUID != "" {
		query += " AND session_uuid = ?"
		args = append(args, sessionUUID)
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying artifacts: %w", err)
	}
	defer rows.Close()

	var artifacts []core.ArtifactRecord
	for rows.Next() {
		var art core.ArtifactRecord
		var tagsJSON, createdAt string
		var runU sql.NullString
		var isSensitive int

		err := rows.Scan(
			&art.UUID, &art.WorkspaceUUID, &runU, &art.SessionUUID,
			&art.ArtifactType, &art.Label,
			&art.ContentHash, &art.StoragePath, &art.ByteSize,
			&createdAt, &art.CreatedBy, &tagsJSON, &isSensitive,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact: %w", err)
		}

		art.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if runU.Valid {
			art.RunUUID = &runU.String
		}
		json.Unmarshal([]byte(tagsJSON), &art.Tags)
		art.IsSensitive = isSensitive != 0

		artifacts = append(artifacts, art)
	}

	return artifacts, nil
}

// VerifyIntegrity checks that all artifact files match their recorded hashes.
func (s *Store) VerifyIntegrity() (valid int, invalid []string, err error) {
	arts, err := s.List("", "")
	if err != nil {
		return 0, nil, err
	}

	for _, art := range arts {
		path := filepath.Join(s.artifactsDir, art.StoragePath)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			invalid = append(invalid, fmt.Sprintf("%s: file missing", art.UUID))
			continue
		}

		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != art.ContentHash {
			invalid = append(invalid, fmt.Sprintf("%s: hash mismatch", art.UUID))
			continue
		}
		valid++
	}

	return valid, invalid, nil
}
