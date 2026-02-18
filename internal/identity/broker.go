// Package identity implements the Identity & Session Broker — the heart of STRATUS.
// It manages credential import, session derivation, and the context stack.
package identity

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/vault"
)

// Broker manages identities and sessions within a workspace.
type Broker struct {
	db            *sql.DB
	vault         *vault.Vault
	audit         *audit.Logger
	workspaceUUID string
}

// NewBroker creates a new identity broker for the given workspace.
func NewBroker(db *sql.DB, v *vault.Vault, al *audit.Logger, workspaceUUID string) *Broker {
	return &Broker{
		db:            db,
		vault:         v,
		audit:         al,
		workspaceUUID: workspaceUUID,
	}
}

// IAMKeyInput holds parameters for importing a long-lived IAM key.
type IAMKeyInput struct {
	AccessKey string
	SecretKey string
	Label     string
	Region    string
	Tags      []string
}

// STSSessionInput holds parameters for importing a pre-captured STS session.
type STSSessionInput struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiry       *time.Time
	Label        string
	Region       string
	Tags         []string
}

// AssumeRoleInput holds parameters for a role assumption identity.
type AssumeRoleInput struct {
	RoleARN         string
	ExternalID      string
	SourceSessionID string
	MFASerial       string
	Label           string
	Tags            []string
}

// WebIdentityInput holds parameters for OIDC/JWT web identity.
type WebIdentityInput struct {
	RoleARN   string
	TokenFile string
	RawToken  string
	Label     string
	Tags      []string
}

// CredProcessInput holds parameters for credential_process identity.
type CredProcessInput struct {
	Command      string
	Label        string
	Tags         []string
	Region       string
	// If the command was already executed, provide the captured credentials:
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiry       *time.Time
}

// IMDSCaptureInput holds parameters for IMDS snapshot import.
// The JSON data should contain at minimum: AccessKeyId, SecretAccessKey, Token.
// Optionally: Expiration (RFC3339), Code, Type.
type IMDSCaptureInput struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiry       *time.Time
	RoleName     string // From the IMDS iam/security-credentials/<role> endpoint
	Label        string
	Region       string
	Tags         []string
}

// ImportIAMKey imports a long-lived IAM access key pair.
func (b *Broker) ImportIAMKey(input IAMKeyInput) (*core.IdentityRecord, *core.SessionRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	// Store secret material in vault
	secretData, _ := json.Marshal(map[string]string{
		"access_key": input.AccessKey,
		"secret_key": input.SecretKey,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, nil, fmt.Errorf("storing credentials in vault: %w", err)
	}

	tagsJSON, _ := json.Marshal(input.Tags)
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		PrincipalType: core.PrincipalIAMUser,
		SourceType:    core.SourceIAMUserKey,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          input.Tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', '', ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting identity: %w", err)
	}

	// Derive initial session
	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	session, err := b.createSession(identityUUID, input.AccessKey, input.Label, region, nil, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating session: %w", err)
	}

	b.audit.Log(audit.EventIdentityImported, "local", session.UUID, "", map[string]string{
		"identity_uuid": identityUUID,
		"source_type":   string(core.SourceIAMUserKey),
		"label":         input.Label,
	})

	if err := b.vault.Save(); err != nil {
		return nil, nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, session, nil
}

// ImportSTSSession imports a pre-captured STS session triple.
func (b *Broker) ImportSTSSession(input STSSessionInput) (*core.IdentityRecord, *core.SessionRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	secretData, _ := json.Marshal(map[string]string{
		"access_key":    input.AccessKey,
		"secret_key":    input.SecretKey,
		"session_token": input.SessionToken,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, nil, fmt.Errorf("storing credentials in vault: %w", err)
	}

	tagsJSON, _ := json.Marshal(input.Tags)
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		PrincipalType: core.PrincipalAssumedRole,
		SourceType:    core.SourceSTSSession,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          input.Tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', '', ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting identity: %w", err)
	}

	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	session, err := b.createSession(identityUUID, input.AccessKey, input.Label, region, input.Expiry, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating session: %w", err)
	}

	b.audit.Log(audit.EventIdentityImported, "local", session.UUID, "", map[string]string{
		"identity_uuid": identityUUID,
		"source_type":   string(core.SourceSTSSession),
		"label":         input.Label,
	})

	if err := b.vault.Save(); err != nil {
		return nil, nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, session, nil
}

// ImportAssumeRole imports a role assumption identity.
func (b *Broker) ImportAssumeRole(input AssumeRoleInput) (*core.IdentityRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	secretData, _ := json.Marshal(map[string]string{
		"role_arn":          input.RoleARN,
		"external_id":      input.ExternalID,
		"source_session_id": input.SourceSessionID,
		"mfa_serial":       input.MFASerial,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, fmt.Errorf("storing role config in vault: %w", err)
	}

	tagsJSON, _ := json.Marshal(input.Tags)
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		PrincipalARN:  input.RoleARN,
		PrincipalType: core.PrincipalIAMRole,
		SourceType:    core.SourceAssumeRole,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          input.Tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label, identity.PrincipalARN,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting identity: %w", err)
	}

	b.audit.Log(audit.EventIdentityImported, "local", "", "", map[string]string{
		"identity_uuid": identityUUID,
		"source_type":   string(core.SourceAssumeRole),
		"label":         input.Label,
		"role_arn":      input.RoleARN,
	})

	if err := b.vault.Save(); err != nil {
		return nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, nil
}

// ImportWebIdentity imports an OIDC/JWT web identity.
func (b *Broker) ImportWebIdentity(input WebIdentityInput) (*core.IdentityRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	secretData, _ := json.Marshal(map[string]string{
		"role_arn":   input.RoleARN,
		"token_file": input.TokenFile,
		"raw_token":  input.RawToken,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, fmt.Errorf("storing web identity in vault: %w", err)
	}

	tagsJSON, _ := json.Marshal(input.Tags)
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		PrincipalARN:  input.RoleARN,
		PrincipalType: core.PrincipalFederated,
		SourceType:    core.SourceWebIdentity,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          input.Tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label, identity.PrincipalARN,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting identity: %w", err)
	}

	if err := b.vault.Save(); err != nil {
		return nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, nil
}

// ImportCredProcess imports a credential_process identity.
// If Credentials are provided (from executing the command), a session is also created.
func (b *Broker) ImportCredProcess(input CredProcessInput) (*core.IdentityRecord, *core.SessionRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	secretMap := map[string]string{
		"command": input.Command,
	}
	if input.AccessKey != "" {
		secretMap["access_key"] = input.AccessKey
		secretMap["secret_key"] = input.SecretKey
		secretMap["session_token"] = input.SessionToken
	}

	secretData, _ := json.Marshal(secretMap)
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, nil, fmt.Errorf("storing cred-process config in vault: %w", err)
	}

	tagsJSON, _ := json.Marshal(input.Tags)
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		PrincipalType: core.PrincipalUnknown,
		SourceType:    core.SourceCredProcess,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          input.Tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', '', ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting identity: %w", err)
	}

	// Create session if credentials were captured
	var session *core.SessionRecord
	if input.AccessKey != "" {
		region := input.Region
		if region == "" {
			region = "us-east-1"
		}
		refreshMethod := "credential_process"
		session, err = b.createSession(identityUUID, input.AccessKey, input.Label, region, input.Expiry, &refreshMethod, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating session: %w", err)
		}

		b.audit.Log(audit.EventIdentityImported, "local", session.UUID, "", map[string]string{
			"identity_uuid": identityUUID,
			"source_type":   string(core.SourceCredProcess),
			"label":         input.Label,
		})
	} else {
		b.audit.Log(audit.EventIdentityImported, "local", "", "", map[string]string{
			"identity_uuid": identityUUID,
			"source_type":   string(core.SourceCredProcess),
			"label":         input.Label,
			"note":          "command stored, not yet executed",
		})
	}

	if err := b.vault.Save(); err != nil {
		return nil, nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, session, nil
}

// ImportIMDSCapture imports credentials captured from an EC2 instance metadata service.
func (b *Broker) ImportIMDSCapture(input IMDSCaptureInput) (*core.IdentityRecord, *core.SessionRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	secretData, _ := json.Marshal(map[string]string{
		"access_key":    input.AccessKey,
		"secret_key":    input.SecretKey,
		"session_token": input.SessionToken,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, nil, fmt.Errorf("storing IMDS credentials in vault: %w", err)
	}

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	tags = append(tags, "imds_capture")
	tagsJSON, _ := json.Marshal(tags)
	now := time.Now().UTC()

	label := input.Label
	if label == "" && input.RoleName != "" {
		label = "imds-" + input.RoleName
	}
	if label == "" {
		label = "imds-capture"
	}

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         label,
		PrincipalType: core.PrincipalAssumedRole,
		SourceType:    core.SourceIMDSCapture,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          tags,
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, '', '', ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting identity: %w", err)
	}

	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	session, err := b.createSession(identityUUID, input.AccessKey, label, region, input.Expiry, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating session: %w", err)
	}

	b.audit.Log(audit.EventIdentityImported, "local", session.UUID, "", map[string]string{
		"identity_uuid": identityUUID,
		"source_type":   string(core.SourceIMDSCapture),
		"label":         label,
		"role_name":     input.RoleName,
	})

	if err := b.vault.Save(); err != nil {
		return nil, nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, session, nil
}

// AssumedRoleSessionInput holds parameters for importing an already-assumed role session.
type AssumedRoleSessionInput struct {
	AccessKey         string
	SecretKey         string
	SessionToken      string
	Expiry            *time.Time
	Label             string
	Region            string
	RoleARN           string
	ExternalID        string
	SourceSessionUUID string
}

// ImportAssumedRoleSession imports credentials from a completed STS AssumeRole call.
// It creates a new identity and session, chained to the source session.
func (b *Broker) ImportAssumedRoleSession(input AssumedRoleSessionInput) (*core.IdentityRecord, *core.SessionRecord, error) {
	identityUUID := uuid.New().String()
	vaultKey := "identity:" + identityUUID

	// Store temporary credentials in vault (include external_id for refresh)
	secretData, _ := json.Marshal(map[string]string{
		"access_key":    input.AccessKey,
		"secret_key":    input.SecretKey,
		"session_token": input.SessionToken,
		"external_id":   input.ExternalID,
	})
	if err := b.vault.Put(vaultKey, secretData); err != nil {
		return nil, nil, fmt.Errorf("storing credentials in vault: %w", err)
	}

	// Extract account ID from role ARN (arn:aws:iam::ACCOUNT:role/Name)
	accountID := ""
	parts := splitARN(input.RoleARN)
	if len(parts) >= 5 {
		accountID = parts[4]
	}

	tagsJSON, _ := json.Marshal([]string{"assumed_role"})
	now := time.Now().UTC()

	identity := &core.IdentityRecord{
		UUID:          identityUUID,
		Label:         input.Label,
		AccountID:     accountID,
		PrincipalARN:  input.RoleARN,
		PrincipalType: core.PrincipalAssumedRole,
		SourceType:    core.SourceAssumeRole,
		VaultKeyRef:   vaultKey,
		AcquiredAt:    now,
		WorkspaceUUID: b.workspaceUUID,
		Tags:          []string{"assumed_role"},
		CreatedBy:     "local",
	}

	_, err := b.db.Exec(
		`INSERT INTO identities (uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		identity.UUID, identity.Label, identity.AccountID, identity.PrincipalARN,
		string(identity.PrincipalType), string(identity.SourceType),
		identity.VaultKeyRef,
		now.Format(time.RFC3339),
		b.workspaceUUID,
		string(tagsJSON),
		identity.CreatedBy,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting identity: %w", err)
	}

	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	refreshMethod := "assume_role"
	session, err := b.createSession(identityUUID, input.AccessKey, input.Label, region, input.Expiry, &refreshMethod, &input.SourceSessionUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("creating session: %w", err)
	}

	b.audit.Log(audit.EventSessionActivated, "local", session.UUID, "", map[string]string{
		"identity_uuid":       identityUUID,
		"source_type":         string(core.SourceAssumeRole),
		"role_arn":            input.RoleARN,
		"source_session_uuid": input.SourceSessionUUID,
		"label":               input.Label,
	})

	if err := b.vault.Save(); err != nil {
		return nil, nil, fmt.Errorf("saving vault: %w", err)
	}

	return identity, session, nil
}

// splitARN splits an ARN string by colon delimiter.
func splitARN(arn string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(arn); i++ {
		if arn[i] == ':' {
			parts = append(parts, arn[start:i])
			start = i + 1
		}
	}
	parts = append(parts, arn[start:])
	return parts
}

// ListIdentities returns all non-archived identities in the workspace.
func (b *Broker) ListIdentities() ([]core.IdentityRecord, error) {
	rows, err := b.db.Query(
		`SELECT uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, risk_notes, is_archived, created_by
		 FROM identities WHERE workspace_uuid = ? AND is_archived = 0 ORDER BY acquired_at DESC`,
		b.workspaceUUID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying identities: %w", err)
	}
	defer rows.Close()

	var identities []core.IdentityRecord
	for rows.Next() {
		var id core.IdentityRecord
		var tagsJSON, acquiredAt string
		var isArchived int
		err := rows.Scan(
			&id.UUID, &id.Label, &id.AccountID, &id.PrincipalARN,
			&id.PrincipalType, &id.SourceType, &id.VaultKeyRef,
			&acquiredAt, &id.WorkspaceUUID, &tagsJSON,
			&id.RiskNotes, &isArchived, &id.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning identity: %w", err)
		}
		id.AcquiredAt, _ = time.Parse(time.RFC3339, acquiredAt)
		json.Unmarshal([]byte(tagsJSON), &id.Tags)
		id.IsArchived = isArchived != 0
		identities = append(identities, id)
	}
	return identities, nil
}

// GetIdentity returns a single identity by UUID or label.
func (b *Broker) GetIdentity(uuidOrLabel string) (*core.IdentityRecord, error) {
	var id core.IdentityRecord
	var tagsJSON, acquiredAt string
	var isArchived int

	err := b.db.QueryRow(
		`SELECT uuid, label, account_id, principal_arn, principal_type, source_type, vault_key_ref, acquired_at, workspace_uuid, tags, risk_notes, is_archived, created_by
		 FROM identities WHERE workspace_uuid = ? AND (uuid = ? OR label = ?) LIMIT 1`,
		b.workspaceUUID, uuidOrLabel, uuidOrLabel,
	).Scan(
		&id.UUID, &id.Label, &id.AccountID, &id.PrincipalARN,
		&id.PrincipalType, &id.SourceType, &id.VaultKeyRef,
		&acquiredAt, &id.WorkspaceUUID, &tagsJSON,
		&id.RiskNotes, &isArchived, &id.CreatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("identity not found: %s", uuidOrLabel)
		}
		return nil, fmt.Errorf("querying identity: %w", err)
	}

	id.AcquiredAt, _ = time.Parse(time.RFC3339, acquiredAt)
	json.Unmarshal([]byte(tagsJSON), &id.Tags)
	id.IsArchived = isArchived != 0
	return &id, nil
}

// ArchiveIdentity soft-deletes an identity.
func (b *Broker) ArchiveIdentity(uuidOrLabel string) error {
	result, err := b.db.Exec(
		"UPDATE identities SET is_archived = 1 WHERE workspace_uuid = ? AND (uuid = ? OR label = ?)",
		b.workspaceUUID, uuidOrLabel, uuidOrLabel,
	)
	if err != nil {
		return fmt.Errorf("archiving identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("identity not found: %s", uuidOrLabel)
	}
	return nil
}

// UpdateIdentityPrincipal sets the resolved AccountID and PrincipalARN after verification.
func (b *Broker) UpdateIdentityPrincipal(identityUUID, accountID, principalARN string, principalType core.PrincipalType) error {
	_, err := b.db.Exec(
		"UPDATE identities SET account_id = ?, principal_arn = ?, principal_type = ? WHERE uuid = ?",
		accountID, principalARN, string(principalType), identityUUID,
	)
	return err
}

// createSession inserts a new immutable session record.
func (b *Broker) createSession(identityUUID, accessKeyID, sessionName, region string, expiry *time.Time, refreshMethod *string, parentSessionUUID *string) (*core.SessionRecord, error) {
	sessionUUID := uuid.New().String()
	now := time.Now().UTC()

	var expiryStr sql.NullString
	if expiry != nil {
		expiryStr = sql.NullString{String: expiry.Format(time.RFC3339), Valid: true}
	}

	var refreshStr sql.NullString
	if refreshMethod != nil {
		refreshStr = sql.NullString{String: *refreshMethod, Valid: true}
	}

	var parentStr sql.NullString
	if parentSessionUUID != nil {
		parentStr = sql.NullString{String: *parentSessionUUID, Valid: true}
	}

	_, err := b.db.Exec(
		`INSERT INTO sessions (uuid, identity_uuid, aws_access_key_id, session_name, region, expiry, refresh_method, chain_parent_session_uuid, created_at, health_status, is_active, workspace_uuid)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		sessionUUID, identityUUID, accessKeyID, sessionName, region,
		expiryStr, refreshStr, parentStr,
		now.Format(time.RFC3339),
		string(core.HealthUnverified),
		b.workspaceUUID,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting session: %w", err)
	}

	session := &core.SessionRecord{
		UUID:                   sessionUUID,
		IdentityUUID:           identityUUID,
		AWSAccessKeyID:         accessKeyID,
		SessionName:            sessionName,
		Region:                 region,
		Expiry:                 expiry,
		RefreshMethod:          refreshMethod,
		ChainParentSessionUUID: parentSessionUUID,
		CreatedAt:              now,
		HealthStatus:           core.HealthUnverified,
		IsActive:               false,
		WorkspaceUUID:          b.workspaceUUID,
	}

	return session, nil
}
