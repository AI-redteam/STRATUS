package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/graph"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// IAMPolicyAnalyzerModule analyzes IAM policies attached to users and roles
// to identify privilege escalation paths such as iam:PassRole + lambda:CreateFunction,
// iam:PutUserPolicy, sts:AssumeRole with wildcard, etc.
type IAMPolicyAnalyzerModule struct {
	factory *aws.ClientFactory
	graph   *graph.Store
}

// privescPattern describes a privilege escalation technique.
type privescPattern struct {
	Name        string
	Description string
	Actions     []string // all must be present
	Reference   string
}

var knownPrivescPatterns = []privescPattern{
	{
		Name:        "CreatePolicyVersion",
		Description: "Can create a new policy version with admin privileges",
		Actions:     []string{"iam:CreatePolicyVersion"},
		Reference:   "T1098",
	},
	{
		Name:        "SetDefaultPolicyVersion",
		Description: "Can switch default policy version to a permissive one",
		Actions:     []string{"iam:SetDefaultPolicyVersion"},
		Reference:   "T1098",
	},
	{
		Name:        "AttachUserPolicy",
		Description: "Can attach any managed policy (including AdministratorAccess) to a user",
		Actions:     []string{"iam:AttachUserPolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "AttachRolePolicy",
		Description: "Can attach any managed policy to a role",
		Actions:     []string{"iam:AttachRolePolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "AttachGroupPolicy",
		Description: "Can attach any managed policy to a group",
		Actions:     []string{"iam:AttachGroupPolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "PutUserPolicy",
		Description: "Can create an inline admin policy on a user",
		Actions:     []string{"iam:PutUserPolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "PutRolePolicy",
		Description: "Can create an inline admin policy on a role",
		Actions:     []string{"iam:PutRolePolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "PutGroupPolicy",
		Description: "Can create an inline admin policy on a group",
		Actions:     []string{"iam:PutGroupPolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "AddUserToGroup",
		Description: "Can add user to admin group",
		Actions:     []string{"iam:AddUserToGroup"},
		Reference:   "T1098",
	},
	{
		Name:        "CreateAccessKey",
		Description: "Can create access keys for other users",
		Actions:     []string{"iam:CreateAccessKey"},
		Reference:   "T1098.001",
	},
	{
		Name:        "CreateLoginProfile",
		Description: "Can create console login for users without one",
		Actions:     []string{"iam:CreateLoginProfile"},
		Reference:   "T1098",
	},
	{
		Name:        "UpdateLoginProfile",
		Description: "Can change passwords for other users",
		Actions:     []string{"iam:UpdateLoginProfile"},
		Reference:   "T1098",
	},
	{
		Name:        "LambdaPrivesc",
		Description: "Can create Lambda with privileged role and invoke it",
		Actions:     []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
		Reference:   "T1098",
	},
	{
		Name:        "LambdaCodeUpdate",
		Description: "Can update existing Lambda function code to inject malicious logic",
		Actions:     []string{"lambda:UpdateFunctionCode"},
		Reference:   "T1525",
	},
	{
		Name:        "EC2Privesc",
		Description: "Can launch EC2 instance with privileged role and access via IMDS",
		Actions:     []string{"iam:PassRole", "ec2:RunInstances"},
		Reference:   "T1098",
	},
	{
		Name:        "UpdateAssumeRolePolicy",
		Description: "Can modify role trust policy to allow own assumption",
		Actions:     []string{"iam:UpdateAssumeRolePolicy"},
		Reference:   "T1098",
	},
	{
		Name:        "CloudFormationPrivesc",
		Description: "Can create CloudFormation stack with privileged role",
		Actions:     []string{"iam:PassRole", "cloudformation:CreateStack"},
		Reference:   "T1098",
	},
	{
		Name:        "GluePrivesc",
		Description: "Can create Glue dev endpoint with privileged role",
		Actions:     []string{"iam:PassRole", "glue:CreateDevEndpoint"},
		Reference:   "T1098",
	},
	{
		Name:        "SageMakerPrivesc",
		Description: "Can create SageMaker notebook with privileged role",
		Actions:     []string{"iam:PassRole", "sagemaker:CreateNotebookInstance"},
		Reference:   "T1098",
	},
	{
		Name:        "AssumeRoleWildcard",
		Description: "Can assume any role via sts:AssumeRole with wildcard resource",
		Actions:     []string{"sts:AssumeRole"},
		Reference:   "T1550",
	},
}

func (m *IAMPolicyAnalyzerModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.iam.policy-analyzer",
		Name:        "IAM Privilege Escalation Analyzer",
		Version:     "1.0.0",
		Description: "Analyzes IAM policies attached to users and roles to detect privilege escalation paths. Checks for dangerous permission combinations like iam:PassRole + lambda:CreateFunction, iam:PutUserPolicy, iam:AttachRolePolicy, and 18 other known escalation vectors.",
		Services:    []string{"iam"},
		RequiredActions: []string{
			"iam:ListUsers",
			"iam:ListRoles",
			"iam:ListAttachedUserPolicies",
			"iam:ListAttachedRolePolicies",
			"iam:ListUserPolicies",
			"iam:ListRolePolicies",
			"iam:GetPolicy",
			"iam:GetPolicyVersion",
			"iam:GetUserPolicy",
			"iam:GetRolePolicy",
		},
		RequiredResources: []string{"arn:aws:iam::*:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "scan_users", Type: "bool", Default: true, Description: "Scan IAM users for privesc paths"},
			{Name: "scan_roles", Type: "bool", Default: true, Description: "Scan IAM roles for privesc paths"},
			{Name: "max_principals", Type: "int", Default: 200, Description: "Maximum principals to analyze"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "principals_scanned", Type: "int", Description: "Total users/roles scanned"},
			{Name: "privesc_paths", Type: "[]map", Description: "Detected privilege escalation paths"},
			{Name: "high_risk_count", Type: "int", Description: "Number of unique principals with privesc paths"},
			{Name: "admin_principals", Type: "[]string", Description: "Principals with full admin access"},
			{Name: "warnings", Type: "[]string", Description: "Non-fatal errors encountered during analysis"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1098/",
			"https://attack.mitre.org/techniques/T1078/004/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "IAM", SortOrder: 3},
	}
}

func (m *IAMPolicyAnalyzerModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"iam:ListUsers", "iam:ListRoles",
			"iam:ListAttachedUserPolicies (per user)", "iam:ListAttachedRolePolicies (per role)",
			"iam:GetPolicy + iam:GetPolicyVersion (per attached policy)",
			"iam:GetUserPolicy (per inline policy)", "iam:GetRolePolicy (per inline policy)",
		},
		Confidence: 1.0,
	}
}

func (m *IAMPolicyAnalyzerModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate users and roles, retrieve all attached and inline policies, then analyze each policy document for privilege escalation patterns.",
		WouldMutate: false,
		APICalls:    []string{"iam:ListUsers", "iam:ListRoles", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetUserPolicy", "iam:GetRolePolicy"},
	}
}

func (m *IAMPolicyAnalyzerModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	scanUsers := ctx.InputBool("scan_users")
	scanRoles := ctx.InputBool("scan_roles")
	maxPrincipals := ctx.InputInt("max_principals")
	if maxPrincipals <= 0 {
		maxPrincipals = 200
	}

	type principalInfo struct {
		principalType string // "user" or "role"
		name          string
		arn           string
	}

	var principals []principalInfo

	if scanUsers {
		users, err := m.factory.ListIAMUsers(bgCtx, creds)
		if err == nil {
			for _, u := range users {
				principals = append(principals, principalInfo{"user", u.UserName, u.ARN})
			}
		}
	}

	if scanRoles {
		roles, err := m.factory.ListIAMRoles(bgCtx, creds)
		if err == nil {
			for _, r := range roles {
				principals = append(principals, principalInfo{"role", r.RoleName, r.ARN})
			}
		}
	}

	if len(principals) > maxPrincipals {
		principals = principals[:maxPrincipals]
	}

	prog.Total(len(principals))

	var privescPaths []map[string]any
	var adminPrincipals []string
	var warnings []string
	riskyPrincipals := make(map[string]bool)

	for i, p := range principals {
		prog.Update(i+1, fmt.Sprintf("Analyzing %s: %s", p.principalType, p.name))

		// Collect all actions from all policies for this principal
		actions, errs := m.collectPrincipalActions(bgCtx, creds, p.principalType, p.name)
		for _, e := range errs {
			warnings = append(warnings, fmt.Sprintf("%s %s: %s", p.principalType, p.name, e))
		}
		if len(actions) == 0 {
			continue
		}

		// Check for full admin
		if actions["*"] {
			adminPrincipals = append(adminPrincipals, p.arn)
			riskyPrincipals[p.arn] = true
			privescPaths = append(privescPaths, map[string]any{
				"principal_type": p.principalType,
				"principal_name": p.name,
				"principal_arn":  p.arn,
				"finding":        "FullAdmin",
				"description":    "Has * (all) permissions — full administrator access",
				"severity":       "critical",
			})
			continue
		}

		// Check for known privesc patterns
		for _, pattern := range knownPrivescPatterns {
			if matchesPrivescPattern(actions, pattern) {
				riskyPrincipals[p.arn] = true
				privescPaths = append(privescPaths, map[string]any{
					"principal_type": p.principalType,
					"principal_name": p.name,
					"principal_arn":  p.arn,
					"finding":        pattern.Name,
					"description":    pattern.Description,
					"required_actions": pattern.Actions,
					"severity":       "high",
					"reference":      pattern.Reference,
				})
			}
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"principals_scanned": len(principals),
			"privesc_paths":      privescPaths,
			"high_risk_count":    len(riskyPrincipals),
			"admin_principals":   adminPrincipals,
			"warnings":           warnings,
		},
	}
}

func (m *IAMPolicyAnalyzerModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// collectPrincipalActions gathers all allowed actions from all policies for a principal.
// Returns the action set and any non-fatal errors encountered during collection.
func (m *IAMPolicyAnalyzerModule) collectPrincipalActions(ctx context.Context, creds aws.SessionCredentials, principalType, name string) (map[string]bool, []string) {
	actions := make(map[string]bool)
	var warnings []string

	if principalType == "user" {
		detail, err := m.factory.GetIAMUserDetail(ctx, creds, name)
		if err != nil {
			return actions, []string{fmt.Sprintf("failed to get user detail: %v", err)}
		}

		// Attached managed policies
		for _, policyARN := range detail.AttachedPolicies {
			if err := m.extractManagedPolicyActions(ctx, creds, policyARN, actions); err != nil {
				warnings = append(warnings, fmt.Sprintf("policy %s: %v", policyARN, err))
			}
		}

		// Inline policies
		for _, policyName := range detail.InlinePolicies {
			doc, err := m.factory.GetIAMUserInlinePolicy(ctx, creds, name, policyName)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("inline policy %s: %v", policyName, err))
			} else {
				extractActionsFromDocument(doc, actions)
			}
		}
	} else {
		detail, err := m.factory.GetIAMRoleDetail(ctx, creds, name)
		if err != nil {
			return actions, []string{fmt.Sprintf("failed to get role detail: %v", err)}
		}

		for _, policyARN := range detail.AttachedPolicies {
			if err := m.extractManagedPolicyActions(ctx, creds, policyARN, actions); err != nil {
				warnings = append(warnings, fmt.Sprintf("policy %s: %v", policyARN, err))
			}
		}

		for _, policyName := range detail.InlinePolicies {
			doc, err := m.factory.GetIAMRoleInlinePolicy(ctx, creds, name, policyName)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("inline policy %s: %v", policyName, err))
			} else {
				extractActionsFromDocument(doc, actions)
			}
		}
	}

	return actions, warnings
}

// extractManagedPolicyActions retrieves and parses a managed policy document.
func (m *IAMPolicyAnalyzerModule) extractManagedPolicyActions(ctx context.Context, creds aws.SessionCredentials, policyARN string, actions map[string]bool) error {
	versionID, _, err := m.factory.GetIAMPolicyDefaultVersion(ctx, creds, policyARN)
	if err != nil {
		return fmt.Errorf("getting default version: %w", err)
	}

	doc, err := m.factory.GetIAMPolicyVersion(ctx, creds, policyARN, versionID)
	if err != nil {
		return fmt.Errorf("getting policy version %s: %w", versionID, err)
	}

	extractActionsFromDocument(doc, actions)
	return nil
}

// extractActionsFromDocument parses an IAM policy document and extracts allowed actions.
func extractActionsFromDocument(policyDoc string, actions map[string]bool) {
	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		decoded = policyDoc
	}

	var doc struct {
		Statement []struct {
			Effect   string      `json:"Effect"`
			Action   interface{} `json:"Action"`
			Resource interface{} `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		// Check if resource is wildcard (most privesc requires * resource)
		resourceIsWild := isWildcardResource(stmt.Resource)

		switch a := stmt.Action.(type) {
		case string:
			if resourceIsWild || a == "*" {
				actions[a] = true
			}
		case []interface{}:
			for _, item := range a {
				if s, ok := item.(string); ok {
					if resourceIsWild || s == "*" {
						actions[s] = true
					}
				}
			}
		}
	}
}

// isWildcardResource checks if a Resource field includes "*".
func isWildcardResource(resource interface{}) bool {
	switch r := resource.(type) {
	case string:
		return r == "*"
	case []interface{}:
		for _, item := range r {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

// matchesPrivescPattern checks if a principal's actions match a privesc pattern.
func matchesPrivescPattern(actions map[string]bool, pattern privescPattern) bool {
	for _, required := range pattern.Actions {
		if !actionMatches(actions, required) {
			return false
		}
	}
	return true
}

// actionMatches checks if any action in the set matches the required action,
// accounting for wildcard patterns like "iam:*" or "*".
func actionMatches(actions map[string]bool, required string) bool {
	if actions["*"] {
		return true
	}
	if actions[required] {
		return true
	}
	// Check service-level wildcards (e.g., "iam:*" matches "iam:CreatePolicyVersion")
	parts := strings.SplitN(required, ":", 2)
	if len(parts) == 2 {
		if actions[parts[0]+":*"] {
			return true
		}
	}
	return false
}
