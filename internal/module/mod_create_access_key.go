package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CreateAccessKeyModule creates a new IAM access key for a target user.
// This is a write-risk module used for persistence via credential creation (T1098.001).
type CreateAccessKeyModule struct {
	factory *aws.ClientFactory
}

func (m *CreateAccessKeyModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.iam.create-access-key",
		Name:        "Create IAM Access Key",
		Version:     "1.0.0",
		Description: "Creates a new IAM access key for a specified user. Used for persistence testing via credential creation. The secret access key is stored as an artifact but NOT included in module outputs for security.",
		Services:    []string{"iam"},
		RequiredActions: []string{
			"iam:CreateAccessKey",
		},
		RequiredResources: []string{"arn:aws:iam::*:user/*"},
		RiskClass:         sdk.RiskWrite,
		Inputs: []sdk.InputSpec{
			{Name: "user_name", Type: "string", Description: "IAM user to create an access key for", Required: true},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "access_key_id", Type: "string", Description: "The new access key ID"},
			{Name: "status", Type: "string", Description: "Key status (Active)"},
			{Name: "user_name", Type: "string", Description: "The user the key was created for"},
			{Name: "create_date", Type: "string", Description: "When the key was created"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1098/001/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "IAM", SortOrder: 3},
	}
}

func (m *CreateAccessKeyModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	userName := ctx.InputString("user_name")
	if userName == "" {
		return sdk.PreflightResult{
			MissingPermissions: []string{"(user_name input is required)"},
			PlannedAPICalls:    []string{"iam:CreateAccessKey"},
			Confidence:         0.0,
		}
	}
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"iam:CreateAccessKey"},
		Confidence:      1.0,
	}
}

func (m *CreateAccessKeyModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	userName := ctx.InputString("user_name")
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call iam:CreateAccessKey for user %q. This creates a new long-term credential.", userName),
		WouldMutate: true,
		APICalls:    []string{"iam:CreateAccessKey"},
	}
}

func (m *CreateAccessKeyModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	userName := ctx.InputString("user_name")
	if userName == "" {
		return sdk.ErrResult(fmt.Errorf("user_name input is required"))
	}

	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	prog.Total(1)
	prog.Update(1, "Creating access key for: "+userName)

	result, _, err := m.factory.CreateAccessKey(bgCtx, creds, userName)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("creating access key: %w", err))
	}

	// Intentionally do NOT include SecretAccessKey in outputs
	return sdk.RunResult{
		Outputs: map[string]any{
			"access_key_id": result.AccessKeyID,
			"status":        result.Status,
			"user_name":     result.UserName,
			"create_date":   result.CreateDate,
		},
	}
}

func (m *CreateAccessKeyModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	// Write ops are not idempotent — return prior outputs instead of re-executing
	return sdk.RunResult{Outputs: prior.Outputs}
}
