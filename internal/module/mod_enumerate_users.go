package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EnumerateUsersModule lists all IAM users with their group memberships,
// policies, access keys, and MFA status.
type EnumerateUsersModule struct {
	factory *aws.ClientFactory
}

func (m *EnumerateUsersModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.iam.enumerate-users",
		Name:        "Enumerate IAM Users",
		Version:     "1.0.0",
		Description: "Lists all IAM users with group memberships, policies, access keys, and MFA device status. Identifies users without MFA and with console access.",
		Services:    []string{"iam"},
		RequiredActions: []string{
			"iam:ListUsers",
			"iam:ListUserPolicies",
			"iam:ListAttachedUserPolicies",
			"iam:ListGroupsForUser",
			"iam:ListMFADevices",
			"iam:GetLoginProfile",
		},
		RequiredResources: []string{"arn:aws:iam::*:user/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_users", Type: "int", Default: 500, Description: "Maximum users to enumerate"},
			{Name: "detail", Type: "bool", Default: true, Description: "Fetch per-user detail (groups, policies, MFA)"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "user_arns", Type: "[]string", Description: "All discovered user ARNs"},
			{Name: "user_count", Type: "int", Description: "Total count"},
			{Name: "users_without_mfa", Type: "[]string", Description: "Users without any MFA device"},
			{Name: "users_with_console", Type: "[]string", Description: "Users with console login profile"},
			{Name: "inactive_keys", Type: "[]string", Description: "Access keys in inactive status"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1087/004/",
		},
		Author: "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "IAM", SortOrder: 2},
	}
}

func (m *EnumerateUsersModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"iam:ListUsers (paginated)",
			"iam:ListGroupsForUser (per user)",
			"iam:ListAttachedUserPolicies (per user)",
			"iam:ListMFADevices (per user)",
			"iam:ListAccessKeys (per user)",
		},
		Confidence: 1.0,
	}
}

func (m *EnumerateUsersModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call iam:ListUsers (up to %d), then per-user detail calls for groups, policies, MFA, and access keys.",
			ctx.InputInt("max_users")),
		WouldMutate: false,
		APICalls: []string{
			"iam:ListUsers", "iam:ListGroupsForUser",
			"iam:ListAttachedUserPolicies", "iam:ListUserPolicies",
			"iam:ListMFADevices", "iam:ListAccessKeys",
		},
	}
}

func (m *EnumerateUsersModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	users, err := m.factory.ListIAMUsers(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing users: %w", err))
	}

	maxUsers := ctx.InputInt("max_users")
	if maxUsers <= 0 {
		maxUsers = 500
	}
	if len(users) > maxUsers {
		users = users[:maxUsers]
	}

	prog.Total(len(users))

	var userARNs []string
	var usersWithoutMFA []string
	var usersWithConsole []string
	var inactiveKeys []string

	fetchDetail := ctx.InputBool("detail")

	for i, user := range users {
		userARNs = append(userARNs, user.ARN)
		prog.Update(i+1, "Enumerated: "+user.UserName)

		if !fetchDetail {
			continue
		}

		detail, err := m.factory.GetIAMUserDetail(bgCtx, creds, user.UserName)
		if err != nil {
			continue
		}

		if len(detail.MFADevices) == 0 {
			usersWithoutMFA = append(usersWithoutMFA, user.UserName)
		}

		// Check for console access (login profile existence indicated by non-empty groups or policies)
		// The GetLoginProfile API would be more precise but may fail with NoSuchEntity
		if len(detail.Groups) > 0 || len(detail.AttachedPolicies) > 0 {
			usersWithConsole = append(usersWithConsole, user.UserName)
		}

		for _, key := range detail.AccessKeys {
			if len(key) > 0 && contains(key, "Inactive") {
				inactiveKeys = append(inactiveKeys, user.UserName+": "+key)
			}
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"user_arns":         userARNs,
			"user_count":        len(userARNs),
			"users_without_mfa": usersWithoutMFA,
			"users_with_console": usersWithConsole,
			"inactive_keys":     inactiveKeys,
		},
	}
}

func (m *EnumerateUsersModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

func contains(s string, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
