package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SecretsManagerEnumerateModule lists Secrets Manager secrets and optionally
// retrieves their values. Maps to MITRE T1552.005 (Cloud Instance Metadata API).
type SecretsManagerEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *SecretsManagerEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.secretsmanager.enumerate",
		Name:        "Enumerate Secrets Manager",
		Version:     "1.0.0",
		Description: "Lists all Secrets Manager secrets in the target region. Optionally retrieves secret values to identify exposed credentials, API keys, and database passwords.",
		Services:    []string{"secretsmanager"},
		RequiredActions: []string{
			"secretsmanager:ListSecrets",
			"secretsmanager:GetSecretValue",
		},
		RequiredResources: []string{"arn:aws:secretsmanager:*:*:secret:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "retrieve_values", Type: "bool", Default: false, Description: "Retrieve actual secret values (requires secretsmanager:GetSecretValue)"},
			{Name: "max_secrets", Type: "int", Default: 500, Description: "Maximum number of secrets to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "secret_count", Type: "int", Description: "Total secrets found"},
			{Name: "secrets", Type: "[]map", Description: "Secret metadata and optionally values"},
			{Name: "secrets_with_values", Type: "int", Description: "Count of secrets with retrieved values"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1552/005/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Secrets Manager", SortOrder: 1},
	}
}

func (m *SecretsManagerEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"secretsmanager:ListSecrets (paginated)"}
	if ctx.InputBool("retrieve_values") {
		calls = append(calls, "secretsmanager:GetSecretValue (per secret)")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *SecretsManagerEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would call secretsmanager:ListSecrets to enumerate all secrets."
	if ctx.InputBool("retrieve_values") {
		desc += " Would also call secretsmanager:GetSecretValue for each secret."
	}
	calls := []string{"secretsmanager:ListSecrets"}
	if ctx.InputBool("retrieve_values") {
		calls = append(calls, "secretsmanager:GetSecretValue")
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    calls,
	}
}

func (m *SecretsManagerEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	secrets, err := m.factory.ListSecrets(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing secrets: %w", err))
	}

	maxSecrets := ctx.InputInt("max_secrets")
	if maxSecrets <= 0 {
		maxSecrets = 500
	}
	if len(secrets) > maxSecrets {
		secrets = secrets[:maxSecrets]
	}

	retrieveValues := ctx.InputBool("retrieve_values")
	prog.Total(len(secrets))

	var results []map[string]any
	retrievedCount := 0

	for i, secret := range secrets {
		prog.Update(i+1, "Processing: "+secret.Name)

		entry := map[string]any{
			"name":          secret.Name,
			"arn":           secret.ARN,
			"description":   secret.Description,
			"last_accessed": secret.LastAccessed,
			"last_changed":  secret.LastChanged,
		}

		if retrieveValues {
			value, err := m.factory.GetSecretValue(bgCtx, creds, secret.ARN)
			if err == nil {
				// Classify the secret type
				entry["value_preview"] = truncateSecret(value, 100)
				entry["value_length"] = len(value)
				entry["looks_like"] = classifySecret(value)
				retrievedCount++
			} else {
				entry["retrieval_error"] = err.Error()
			}
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"secret_count":        len(results),
			"secrets":             results,
			"secrets_with_values": retrievedCount,
		},
	}
}

func (m *SecretsManagerEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// truncateSecret returns a truncated preview of a secret value.
func truncateSecret(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "...[truncated]"
}

// classifySecret attempts to identify what type of secret a value is.
func classifySecret(value string) string {
	v := strings.TrimSpace(value)
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
		return "json"
	}
	if strings.HasPrefix(v, "AKIA") {
		return "aws_access_key"
	}
	if strings.HasPrefix(v, "-----BEGIN") {
		return "pem_certificate"
	}
	if strings.Contains(v, "://") && strings.Contains(v, "@") {
		return "connection_string"
	}
	return "unknown"
}
