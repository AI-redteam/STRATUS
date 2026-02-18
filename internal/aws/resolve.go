package aws

import (
	"encoding/json"
	"fmt"

	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/session"
	"github.com/stratus-framework/stratus/internal/vault"
)

// ResolveActiveCredentials looks up the active session's credentials from the
// vault and returns them as SessionCredentials ready for AWS API calls.
func ResolveActiveCredentials(engine *core.Engine) (SessionCredentials, *core.SessionRecord, error) {
	mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
	sess, err := mgr.GetActiveSession()
	if err != nil {
		return SessionCredentials{}, nil, err
	}

	return resolveFromSession(engine, sess)
}

// ResolveSessionCredentials resolves credentials for a specific session UUID.
func ResolveSessionCredentials(engine *core.Engine, sessionUUID string) (SessionCredentials, *core.SessionRecord, error) {
	mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
	sess, err := mgr.GetSession(sessionUUID)
	if err != nil {
		return SessionCredentials{}, nil, err
	}
	return resolveFromSession(engine, sess)
}

func resolveFromSession(engine *core.Engine, sess *core.SessionRecord) (SessionCredentials, *core.SessionRecord, error) {
	// Look up the identity vault key
	vaultKey := "identity:" + sess.IdentityUUID
	return resolveFromVault(engine.Vault, sess, vaultKey)
}

func resolveFromVault(v *vault.Vault, sess *core.SessionRecord, vaultKey string) (SessionCredentials, *core.SessionRecord, error) {
	raw, err := v.Get(vaultKey)
	if err != nil {
		return SessionCredentials{}, nil, fmt.Errorf("retrieving credentials from vault: %w", err)
	}

	var credMap map[string]string
	if err := json.Unmarshal(raw, &credMap); err != nil {
		return SessionCredentials{}, nil, fmt.Errorf("parsing credential material: %w", err)
	}

	creds := SessionCredentials{
		AccessKeyID:    credMap["access_key"],
		SecretAccessKey: credMap["secret_key"],
		SessionToken:   credMap["session_token"],
		Region:         sess.Region,
	}

	if creds.AccessKeyID == "" {
		return SessionCredentials{}, nil, fmt.Errorf("no access_key found in vault for identity %s", sess.IdentityUUID)
	}

	return creds, sess, nil
}
