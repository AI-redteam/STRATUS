// Package core defines the foundational types and primitives for the STRATUS framework.
// These six primitives (Workspace, Identity, Session, Scope, Module, Artifact) organize
// every operation and are enforced across the data layer, CLI, module API, and GUI.
package core

import (
	"time"
)

// IdentitySourceType enumerates the credential sources STRATUS can import.
type IdentitySourceType string

const (
	SourceIAMUserKey      IdentitySourceType = "iam_user_key"
	SourceSTSSession      IdentitySourceType = "sts_session"
	SourceAssumeRole      IdentitySourceType = "assume_role"
	SourceWebIdentity     IdentitySourceType = "web_identity"
	SourceCredProcess     IdentitySourceType = "credential_process"
	SourceIMDSCapture     IdentitySourceType = "imds_capture"
	SourceSSOSession      IdentitySourceType = "sso_session"
)

// PrincipalType describes the AWS principal behind an identity.
type PrincipalType string

const (
	PrincipalIAMUser      PrincipalType = "iam_user"
	PrincipalIAMRole      PrincipalType = "iam_role"
	PrincipalFederated    PrincipalType = "federated"
	PrincipalAssumedRole  PrincipalType = "assumed_role"
	PrincipalUnknown      PrincipalType = "unknown"
)

// RiskClass categorizes module operational risk.
type RiskClass string

const (
	RiskReadOnly    RiskClass = "read_only"
	RiskWrite       RiskClass = "write"
	RiskDestructive RiskClass = "destructive"
)

// SessionHealth represents the health status of a session.
type SessionHealth string

const (
	HealthHealthy    SessionHealth = "healthy"
	HealthExpired    SessionHealth = "expired"
	HealthUnverified SessionHealth = "unverified"
	HealthError      SessionHealth = "error"
)

// RunStatus tracks a module run's lifecycle.
type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunSuccess   RunStatus = "success"
	RunError     RunStatus = "error"
	RunCancelled RunStatus = "cancelled"
	RunDryRun    RunStatus = "dry_run"
)

// ArtifactType categorizes stored artifacts.
type ArtifactType string

const (
	ArtifactJSONResult    ArtifactType = "json_result"
	ArtifactAPIProof      ArtifactType = "api_proof"
	ArtifactNote          ArtifactType = "note"
	ArtifactGraphSnapshot ArtifactType = "graph_snapshot"
	ArtifactExportBundle  ArtifactType = "export_bundle"
)

// GraphEdgeType categorizes pivot graph relationships.
type GraphEdgeType string

const (
	EdgeCanAssume   GraphEdgeType = "can_assume"
	EdgeCanInvoke   GraphEdgeType = "can_invoke"
	EdgeCanRead     GraphEdgeType = "can_read"
	EdgeCanWrite    GraphEdgeType = "can_write"
	EdgeTrust       GraphEdgeType = "trust"
	EdgeSCPBoundary GraphEdgeType = "scp_boundary"
)

// AuditEventType categorizes audit log entries.
type AuditEventType string

const (
	AuditAPICall          AuditEventType = "api_call"
	AuditSessionActivated AuditEventType = "session_activated"
	AuditIdentityImported AuditEventType = "identity_imported"
	AuditScopeViolation   AuditEventType = "scope_violation"
	AuditSecretShared     AuditEventType = "secret_shared"
	AuditModuleRun        AuditEventType = "module_run"
	AuditWorkspaceCreated AuditEventType = "workspace_created"
	AuditSessionExpired   AuditEventType = "session_expired"
)

// SecretMode determines how secrets are stored at rest.
type SecretMode string

const (
	SecretModeVault      SecretMode = "vault"       // Default: encrypted vault file
	SecretModeOSKeystore SecretMode = "os_keystore"  // MK in OS keyring
	SecretModeMemoryOnly SecretMode = "memory_only"  // No secrets on disk
)

// Workspace is the top-level container for a single engagement.
type Workspace struct {
	UUID              string    `json:"uuid"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Owner             string    `json:"owner"`
	Tags              []string  `json:"tags,omitempty"`
	ScopeConfig       Scope     `json:"scope_config"`
	EncryptionKeyHint string    `json:"encryption_key_hint,omitempty"`
	Path              string    `json:"path"` // Filesystem path to workspace directory
}

// Scope defines the blast radius for a workspace.
type Scope struct {
	AccountIDs         []string          `json:"account_ids,omitempty"`
	OrgID              string            `json:"org_id,omitempty"`
	OUIDs              []string          `json:"ou_ids,omitempty"`
	Regions            []string          `json:"regions,omitempty"`
	Partition          string            `json:"partition,omitempty"` // aws | aws-cn | aws-us-gov
	ResourceTagFilters map[string]string `json:"resource_tag_filters,omitempty"`
}

// IdentityRecord stores a principal credential source.
type IdentityRecord struct {
	UUID          string             `json:"uuid"`
	Label         string             `json:"label"`
	AccountID     string             `json:"account_id"`
	PrincipalARN  string             `json:"principal_arn"`
	PrincipalType PrincipalType      `json:"principal_type"`
	SourceType    IdentitySourceType `json:"source_type"`
	VaultKeyRef   string             `json:"vault_key_ref"` // Opaque pointer into encrypted vault
	AcquiredAt    time.Time          `json:"acquired_at"`
	WorkspaceUUID string             `json:"workspace_uuid"`
	Tags          []string           `json:"tags,omitempty"`
	RiskNotes     string             `json:"risk_notes,omitempty"`
	IsArchived    bool               `json:"is_archived"`
	CreatedBy     string             `json:"created_by"`
}

// SessionRecord represents an active, time-bounded STS context derived from an Identity.
// Sessions are immutable once created.
type SessionRecord struct {
	UUID                   string        `json:"uuid"`
	IdentityUUID           string        `json:"identity_uuid"`
	AWSAccessKeyID         string        `json:"aws_access_key_id"` // Public key ID only
	SessionName            string        `json:"session_name"`
	Region                 string        `json:"region"`
	Expiry                 *time.Time    `json:"expiry,omitempty"`
	RefreshMethod          *string       `json:"refresh_method,omitempty"`
	RefreshConfigRef       string        `json:"refresh_config_ref,omitempty"` // Vault key pointer
	ChainParentSessionUUID *string       `json:"chain_parent_session_uuid,omitempty"`
	CreatedAt              time.Time     `json:"created_at"`
	LastVerifiedAt         *time.Time    `json:"last_verified_at,omitempty"`
	HealthStatus           SessionHealth `json:"health_status"`
	IsActive               bool          `json:"is_active"`
	WorkspaceUUID          string        `json:"workspace_uuid"`
}

// GraphEdge represents a relationship in the pivot graph.
type GraphEdge struct {
	UUID                    string            `json:"uuid"`
	WorkspaceUUID           string            `json:"workspace_uuid"`
	SourceNodeID            string            `json:"source_node_id"`
	TargetNodeID            string            `json:"target_node_id"`
	EdgeType                GraphEdgeType     `json:"edge_type"`
	EvidenceRefs            []string          `json:"evidence_refs,omitempty"`
	APICallsUsed            []string          `json:"api_calls_used,omitempty"`
	DiscoveredBySessionUUID string            `json:"discovered_by_session_uuid"`
	DiscoveredAt            time.Time         `json:"discovered_at"`
	Confidence              float64           `json:"confidence"`
	Constraints             map[string]any    `json:"constraints,omitempty"`
	IsStale                 bool              `json:"is_stale"`
}

// ModuleRun records a single execution of a module.
type ModuleRun struct {
	UUID                  string         `json:"uuid"`
	ModuleID              string         `json:"module_id"`
	ModuleVersion         string         `json:"module_version"`
	SessionUUID           string         `json:"session_uuid"`
	SessionSnapshot       SessionRecord  `json:"session_snapshot"`
	Inputs                map[string]any `json:"inputs,omitempty"`
	Status                RunStatus      `json:"status"`
	StartedAt             time.Time      `json:"started_at"`
	CompletedAt           *time.Time     `json:"completed_at,omitempty"`
	Outputs               map[string]any `json:"outputs,omitempty"`
	ArtifactUUIDs         []string       `json:"artifact_uuids,omitempty"`
	APICallLogUUID        string         `json:"api_call_log_uuid,omitempty"`
	ErrorDetail           *string        `json:"error_detail,omitempty"`
	GraphMutationsApplied []string       `json:"graph_mutations_applied,omitempty"`
	WorkspaceUUID         string         `json:"workspace_uuid"`
	CreatedBy             string         `json:"created_by"`
}

// ArtifactRecord describes an output produced by a module run or manual operation.
type ArtifactRecord struct {
	UUID          string       `json:"uuid"`
	WorkspaceUUID string       `json:"workspace_uuid"`
	RunUUID       *string      `json:"run_uuid,omitempty"`
	SessionUUID   string       `json:"session_uuid"`
	ArtifactType  ArtifactType `json:"artifact_type"`
	Label         string       `json:"label"`
	ContentHash   string       `json:"content_hash"` // SHA-256
	StoragePath   string       `json:"storage_path"` // Relative to workspace artifact dir
	ByteSize      int64        `json:"byte_size"`
	CreatedAt     time.Time    `json:"created_at"`
	CreatedBy     string       `json:"created_by"`
	LinkedNodeIDs []string     `json:"linked_node_ids,omitempty"`
	Tags          []string     `json:"tags,omitempty"`
	IsSensitive   bool         `json:"is_sensitive"`
}

// AuditRecord is an immutable audit log entry.
type AuditRecord struct {
	ID            int64          `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	WorkspaceUUID string         `json:"workspace_uuid"`
	SessionUUID   string         `json:"session_uuid,omitempty"`
	RunUUID       string         `json:"run_uuid,omitempty"`
	Operator      string         `json:"operator"`
	EventType     AuditEventType `json:"event_type"`
	Detail        string         `json:"detail"` // JSON, secrets redacted
	RecordHash    string         `json:"record_hash"` // SHA-256 chain
}

// Note is an operator-created annotation.
type Note struct {
	UUID          string    `json:"uuid"`
	WorkspaceUUID string    `json:"workspace_uuid"`
	SessionUUID   string    `json:"session_uuid,omitempty"`
	RunUUID       string    `json:"run_uuid,omitempty"`
	NodeID        string    `json:"node_id,omitempty"` // Graph node ARN
	Content       string    `json:"content"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	CreatedBy     string    `json:"created_by"`
}
