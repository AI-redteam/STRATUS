package identity

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stratus-framework/stratus/internal/audit"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/vault"
)

const testWS = "ws-test-uuid"

func setupBrokerTest(t *testing.T) (*Broker, *sql.DB) {
	t.Helper()
	dir := t.TempDir()

	// Metadata DB with required tables (no foreign key enforcement for unit tests)
	db, err := sql.Open("sqlite3", filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}

	db.Exec(`CREATE TABLE identities (
		uuid TEXT PRIMARY KEY, label TEXT NOT NULL, account_id TEXT DEFAULT '',
		principal_arn TEXT DEFAULT '', principal_type TEXT DEFAULT 'unknown',
		source_type TEXT NOT NULL, vault_key_ref TEXT NOT NULL, acquired_at TEXT NOT NULL,
		workspace_uuid TEXT NOT NULL, tags TEXT DEFAULT '[]', risk_notes TEXT DEFAULT '',
		is_archived INTEGER DEFAULT 0, created_by TEXT NOT NULL DEFAULT 'local')`)

	db.Exec(`CREATE TABLE sessions (
		uuid TEXT PRIMARY KEY, identity_uuid TEXT NOT NULL,
		aws_access_key_id TEXT DEFAULT '', session_name TEXT DEFAULT '',
		region TEXT DEFAULT 'us-east-1', expiry TEXT, refresh_method TEXT,
		refresh_config_ref TEXT DEFAULT '', chain_parent_session_uuid TEXT,
		created_at TEXT NOT NULL, last_verified_at TEXT,
		health_status TEXT NOT NULL DEFAULT 'unverified',
		is_active INTEGER DEFAULT 0, workspace_uuid TEXT NOT NULL)`)

	// Audit DB
	auditDB, _ := sql.Open("sqlite3", filepath.Join(dir, "audit.db"))
	auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
		workspace_uuid TEXT NOT NULL, session_uuid TEXT DEFAULT '', run_uuid TEXT DEFAULT '',
		operator TEXT NOT NULL DEFAULT 'local', event_type TEXT NOT NULL,
		detail TEXT DEFAULT '{}', record_hash TEXT NOT NULL)`)
	al, _ := audit.NewLogger(auditDB, testWS)

	// Memory-only vault
	v, err := vault.CreateMemoryOnly("test-passphrase")
	if err != nil {
		t.Fatalf("creating vault: %v", err)
	}

	broker := NewBroker(db, v, al, testWS)
	return broker, db
}

func TestImportIAMKey(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	id, sess, err := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Label:     "ci-readonly",
		Region:    "us-west-2",
		Tags:      []string{"ci", "readonly"},
	})
	if err != nil {
		t.Fatalf("import IAM key: %v", err)
	}

	if id.UUID == "" {
		t.Error("expected non-empty identity UUID")
	}
	if id.Label != "ci-readonly" {
		t.Errorf("expected label 'ci-readonly', got %q", id.Label)
	}
	if id.PrincipalType != core.PrincipalIAMUser {
		t.Errorf("expected principal type iam_user, got %s", id.PrincipalType)
	}
	if id.SourceType != core.SourceIAMUserKey {
		t.Errorf("expected source type iam_user_key, got %s", id.SourceType)
	}

	// Session should exist
	if sess == nil {
		t.Fatal("expected session to be created")
	}
	if sess.Region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %s", sess.Region)
	}
	if sess.IdentityUUID != id.UUID {
		t.Error("session identity UUID doesn't match")
	}
	if sess.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected access key in session, got %q", sess.AWSAccessKeyID)
	}

	// Verify vault has the credential
	if !broker.vault.Has(id.VaultKeyRef) {
		t.Error("expected vault to contain credential")
	}
	data, err := broker.vault.Get(id.VaultKeyRef)
	if err != nil {
		t.Fatalf("getting vault data: %v", err)
	}
	var creds map[string]string
	json.Unmarshal(data, &creds)
	if creds["access_key"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Error("vault credential mismatch")
	}
}

func TestImportIAMKeyDefaultRegion(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	_, sess, err := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "secret",
		Label:     "default-region",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if sess.Region != "us-east-1" {
		t.Errorf("expected default region us-east-1, got %s", sess.Region)
	}
}

func TestImportSTSSession(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	expiry := time.Now().Add(1 * time.Hour)
	id, sess, err := broker.ImportSTSSession(STSSessionInput{
		AccessKey:    "ASIAIOSFODNN7EXAMPLE",
		SecretKey:    "secret",
		SessionToken: "FwoGZX...",
		Expiry:       &expiry,
		Label:        "sts-temp",
		Region:       "eu-west-1",
	})
	if err != nil {
		t.Fatalf("import STS session: %v", err)
	}

	if id.PrincipalType != core.PrincipalAssumedRole {
		t.Errorf("expected assumed_role, got %s", id.PrincipalType)
	}
	if id.SourceType != core.SourceSTSSession {
		t.Errorf("expected sts_session, got %s", id.SourceType)
	}
	if sess.Expiry == nil {
		t.Error("expected expiry to be set")
	}
	if sess.Region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %s", sess.Region)
	}
}

func TestImportIMDSCapture(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	expiry := time.Now().Add(6 * time.Hour)
	id, sess, err := broker.ImportIMDSCapture(IMDSCaptureInput{
		AccessKey:    "ASIAEXAMPLE",
		SecretKey:    "secret-key",
		SessionToken: "imds-token",
		Expiry:       &expiry,
		RoleName:     "ec2-instance-role",
		Region:       "ap-southeast-1",
	})
	if err != nil {
		t.Fatalf("import IMDS capture: %v", err)
	}

	if id.SourceType != core.SourceIMDSCapture {
		t.Errorf("expected imds_capture, got %s", id.SourceType)
	}
	if id.Label != "imds-ec2-instance-role" {
		t.Errorf("expected auto-label 'imds-ec2-instance-role', got %q", id.Label)
	}
	if sess.Region != "ap-southeast-1" {
		t.Errorf("expected region ap-southeast-1, got %s", sess.Region)
	}

	// Check tags include imds_capture
	found := false
	for _, tag := range id.Tags {
		if tag == "imds_capture" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'imds_capture' tag")
	}
}

func TestImportIMDSCaptureDefaultLabel(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	id, _, err := broker.ImportIMDSCapture(IMDSCaptureInput{
		AccessKey:    "ASIAEXAMPLE",
		SecretKey:    "secret",
		SessionToken: "token",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if id.Label != "imds-capture" {
		t.Errorf("expected default label 'imds-capture', got %q", id.Label)
	}
}

func TestImportAssumeRole(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	id, err := broker.ImportAssumeRole(AssumeRoleInput{
		RoleARN:    "arn:aws:iam::123456789012:role/Admin",
		ExternalID: "ext-123",
		Label:      "admin-role",
		Tags:       []string{"lateral"},
	})
	if err != nil {
		t.Fatalf("import assume role: %v", err)
	}

	if id.PrincipalType != core.PrincipalIAMRole {
		t.Errorf("expected iam_role, got %s", id.PrincipalType)
	}
	if id.SourceType != core.SourceAssumeRole {
		t.Errorf("expected assume_role, got %s", id.SourceType)
	}
	if id.PrincipalARN != "arn:aws:iam::123456789012:role/Admin" {
		t.Errorf("expected ARN stored, got %q", id.PrincipalARN)
	}
}

func TestImportWebIdentity(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	id, err := broker.ImportWebIdentity(WebIdentityInput{
		RoleARN:  "arn:aws:iam::123456789012:role/OIDCRole",
		RawToken: "eyJhbGci...",
		Label:    "oidc-role",
	})
	if err != nil {
		t.Fatalf("import web identity: %v", err)
	}

	if id.PrincipalType != core.PrincipalFederated {
		t.Errorf("expected federated, got %s", id.PrincipalType)
	}
	if id.SourceType != core.SourceWebIdentity {
		t.Errorf("expected web_identity, got %s", id.SourceType)
	}
}

func TestImportCredProcess(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	// Without credentials (command-only)
	id, sess, err := broker.ImportCredProcess(CredProcessInput{
		Command: "/usr/local/bin/aws-cred-helper",
		Label:   "cred-process-test",
	})
	if err != nil {
		t.Fatalf("import cred process: %v", err)
	}

	if id.SourceType != core.SourceCredProcess {
		t.Errorf("expected credential_process, got %s", id.SourceType)
	}
	if id.PrincipalType != core.PrincipalUnknown {
		t.Errorf("expected unknown principal, got %s", id.PrincipalType)
	}
	if sess != nil {
		t.Error("expected no session when command not executed")
	}
}

func TestImportCredProcessWithCredentials(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	expiry := time.Now().Add(1 * time.Hour)
	id, sess, err := broker.ImportCredProcess(CredProcessInput{
		Command:      "aws-vault exec profile",
		Label:        "cred-process-with-creds",
		AccessKey:    "ASIAEXAMPLE",
		SecretKey:    "secret",
		SessionToken: "token",
		Expiry:       &expiry,
		Region:       "us-west-2",
	})
	if err != nil {
		t.Fatalf("import cred process with creds: %v", err)
	}

	if id.SourceType != core.SourceCredProcess {
		t.Errorf("expected credential_process, got %s", id.SourceType)
	}
	if sess == nil {
		t.Fatal("expected session when credentials provided")
	}
	if sess.Region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %s", sess.Region)
	}
	if sess.RefreshMethod == nil || *sess.RefreshMethod != "credential_process" {
		t.Error("expected refresh_method credential_process")
	}
}

func TestImportAssumedRoleSession(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	// First create a source session
	_, srcSess, _ := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "secret",
		Label:     "source-key",
	})

	expiry := time.Now().Add(1 * time.Hour)
	id, sess, err := broker.ImportAssumedRoleSession(AssumedRoleSessionInput{
		AccessKey:         "ASIAASSUMED",
		SecretKey:         "assumed-secret",
		SessionToken:      "assumed-token",
		Expiry:            &expiry,
		Label:             "assumed-admin",
		Region:            "us-east-1",
		RoleARN:           "arn:aws:iam::123456789012:role/Admin",
		ExternalID:        "ext-456",
		SourceSessionUUID: srcSess.UUID,
	})
	if err != nil {
		t.Fatalf("import assumed role session: %v", err)
	}

	if id.AccountID != "123456789012" {
		t.Errorf("expected account 123456789012, got %q", id.AccountID)
	}
	if id.PrincipalARN != "arn:aws:iam::123456789012:role/Admin" {
		t.Errorf("expected role ARN, got %q", id.PrincipalARN)
	}
	if sess.RefreshMethod == nil || *sess.RefreshMethod != "assume_role" {
		t.Error("expected refresh_method assume_role")
	}
	if sess.ChainParentSessionUUID == nil || *sess.ChainParentSessionUUID != srcSess.UUID {
		t.Error("expected chain parent session UUID to match source")
	}
}

func TestListIdentities(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	broker.ImportIAMKey(IAMKeyInput{AccessKey: "AKIA1", SecretKey: "s1", Label: "key-one"})
	broker.ImportIAMKey(IAMKeyInput{AccessKey: "AKIA2", SecretKey: "s2", Label: "key-two"})

	ids, err := broker.ListIdentities()
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 identities, got %d", len(ids))
	}
}

func TestGetIdentity(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	created, _, _ := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "secret",
		Label:     "get-test",
	})

	// Get by UUID
	got, err := broker.GetIdentity(created.UUID)
	if err != nil {
		t.Fatalf("get by UUID: %v", err)
	}
	if got.Label != "get-test" {
		t.Errorf("expected label 'get-test', got %q", got.Label)
	}

	// Get by label
	got, err = broker.GetIdentity("get-test")
	if err != nil {
		t.Fatalf("get by label: %v", err)
	}
	if got.UUID != created.UUID {
		t.Error("get by label returned wrong identity")
	}

	// Get nonexistent
	_, err = broker.GetIdentity("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent identity")
	}
}

func TestArchiveIdentity(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	created, _, _ := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "secret",
		Label:     "archive-test",
	})

	// Archive by UUID
	err := broker.ArchiveIdentity(created.UUID)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	// Should not appear in list
	ids, _ := broker.ListIdentities()
	if len(ids) != 0 {
		t.Errorf("expected 0 non-archived identities, got %d", len(ids))
	}

	// Archive by label (should fail since already archived, but still find it)
	err = broker.ArchiveIdentity("nonexistent-label")
	if err == nil {
		t.Error("expected error for nonexistent identity")
	}
}

func TestUpdateIdentityPrincipal(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	created, _, _ := broker.ImportIAMKey(IAMKeyInput{
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "secret",
		Label:     "update-principal",
	})

	err := broker.UpdateIdentityPrincipal(
		created.UUID,
		"123456789012",
		"arn:aws:iam::123456789012:user/testuser",
		core.PrincipalIAMUser,
	)
	if err != nil {
		t.Fatalf("update principal: %v", err)
	}

	got, _ := broker.GetIdentity(created.UUID)
	if got.AccountID != "123456789012" {
		t.Errorf("expected account_id 123456789012, got %q", got.AccountID)
	}
	if got.PrincipalARN != "arn:aws:iam::123456789012:user/testuser" {
		t.Errorf("expected ARN update, got %q", got.PrincipalARN)
	}
}

func TestSplitARN(t *testing.T) {
	tests := []struct {
		arn      string
		expected int
	}{
		{"arn:aws:iam::123456789012:role/Admin", 6},
		{"arn:aws-cn:iam::999888777666:user/test", 6},
		{"short", 1},
		{"a:b:c", 3},
	}

	for _, tt := range tests {
		parts := splitARN(tt.arn)
		if len(parts) != tt.expected {
			t.Errorf("splitARN(%q): expected %d parts, got %d: %v", tt.arn, tt.expected, len(parts), parts)
		}
	}

	// Verify account ID extraction from standard ARN
	parts := splitARN("arn:aws:iam::123456789012:role/Admin")
	if parts[4] != "123456789012" {
		t.Errorf("expected account ID '123456789012', got %q", parts[4])
	}
}

func TestMultipleImportsWithVaultPersistence(t *testing.T) {
	broker, db := setupBrokerTest(t)
	defer db.Close()

	// Import several identities
	id1, _, _ := broker.ImportIAMKey(IAMKeyInput{AccessKey: "AKIA1", SecretKey: "s1", Label: "key1"})
	id2, _, _ := broker.ImportSTSSession(STSSessionInput{
		AccessKey: "ASIA2", SecretKey: "s2", SessionToken: "tok2", Label: "sts2",
	})
	id3, _, _ := broker.ImportIMDSCapture(IMDSCaptureInput{
		AccessKey: "ASIA3", SecretKey: "s3", SessionToken: "tok3", Label: "imds3",
	})

	// All should have vault entries
	for _, id := range []*core.IdentityRecord{id1, id2, id3} {
		if !broker.vault.Has(id.VaultKeyRef) {
			t.Errorf("vault missing entry for %s", id.Label)
		}
	}

	// List should show all 3
	ids, _ := broker.ListIdentities()
	if len(ids) != 3 {
		t.Errorf("expected 3 identities, got %d", len(ids))
	}
}
