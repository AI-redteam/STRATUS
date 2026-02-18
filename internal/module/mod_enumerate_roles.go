package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EnumerateRolesModule lists all IAM roles, extracts trust policies, and
// populates the pivot graph with can_assume edges.
type EnumerateRolesModule struct {
	factory *aws.ClientFactory
	graph   *graph.Store
}

func (m *EnumerateRolesModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.iam.enumerate-roles",
		Name:        "Enumerate IAM Roles",
		Version:     "1.0.0",
		Description: "Lists all IAM roles in the target account, extracts trust policies, and populates the pivot graph with can_assume edges.",
		Services:    []string{"iam"},
		RequiredActions: []string{
			"iam:ListRoles",
			"iam:GetRole",
			"iam:ListAttachedRolePolicies",
		},
		RequiredResources: []string{"arn:aws:iam::*:role/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_roles", Type: "int", Default: 1000, Description: "Maximum roles to enumerate"},
			{Name: "path_prefix", Type: "string", Default: "/", Description: "IAM path prefix filter"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "role_arns", Type: "[]string", Description: "All discovered role ARNs"},
			{Name: "role_count", Type: "int", Description: "Total count"},
			{Name: "trust_edges", Type: "int", Description: "Trust policy edges added to graph"},
		},
		GraphMutations: []sdk.GraphMutationSpec{
			{EdgeType: "can_assume", SourcePattern: "*", TargetPattern: "arn:aws:iam::*:role/*"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1069/003/",
		},
		Author: "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "IAM", SortOrder: 1},
	}
}

func (m *EnumerateRolesModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"iam:ListRoles (paginated)", "iam:GetRole (per role)"},
		Confidence:      1.0,
	}
}

func (m *EnumerateRolesModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call iam:ListRoles with PathPrefix=%s up to max_roles=%d, then iam:GetRole for each to extract trust policies.",
			ctx.InputString("path_prefix"), ctx.InputInt("max_roles")),
		WouldMutate: false,
		APICalls:    []string{"iam:ListRoles", "iam:GetRole", "iam:ListAttachedRolePolicies"},
	}
}

func (m *EnumerateRolesModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{
		Region: ctx.Session.Region,
	}

	bgCtx := context.Background()
	roles, err := m.factory.ListIAMRoles(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing roles: %w", err))
	}

	maxRoles := ctx.InputInt("max_roles")
	if maxRoles <= 0 {
		maxRoles = 1000
	}
	if len(roles) > maxRoles {
		roles = roles[:maxRoles]
	}

	prog.Total(len(roles))

	var roleARNs []string
	trustEdges := 0

	for i, role := range roles {
		roleARNs = append(roleARNs, role.ARN)
		prog.Update(i+1, "Enumerated: "+role.RoleName)

		// Get role detail for trust policy
		detail, err := m.factory.GetIAMRoleDetail(bgCtx, creds, role.RoleName)
		if err != nil {
			continue
		}

		// Parse trust policy and emit graph edges
		if m.graph != nil && detail.AssumeRolePolicyDoc != "" {
			edges := m.parseTrustPolicyEdges(detail.AssumeRolePolicyDoc, role.ARN, ctx.Session.UUID)
			trustEdges += edges

			// Add role as node
			m.graph.AddNode(role.ARN, "iam_role", role.RoleName, ctx.Session.UUID, map[string]any{
				"role_id":          role.RoleID,
				"attached_policies": detail.AttachedPolicies,
				"inline_policies":  detail.InlinePolicies,
			})
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"role_arns":   roleARNs,
			"role_count":  len(roleARNs),
			"trust_edges": trustEdges,
		},
	}
}

func (m *EnumerateRolesModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

func (m *EnumerateRolesModule) parseTrustPolicyEdges(policyDoc, roleARN, sessionUUID string) int {
	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		decoded = policyDoc
	}

	var doc struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
			Condition interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return 0
	}

	edges := 0
	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		principals := extractStmtPrincipals(stmt.Principal)
		for _, principal := range principals {
			edge := core.GraphEdge{
				SourceNodeID:            principal,
				TargetNodeID:            roleARN,
				EdgeType:                core.EdgeCanAssume,
				APICallsUsed:            []string{"iam:GetRole"},
				DiscoveredBySessionUUID: sessionUUID,
				DiscoveredAt:            time.Now().UTC(),
				Confidence:              0.95,
			}
			if _, err := m.graph.AddEdge(edge); err == nil {
				edges++
			}
		}
	}
	return edges
}

func extractStmtPrincipals(principal interface{}) []string {
	var result []string
	switch p := principal.(type) {
	case string:
		result = append(result, p)
	case map[string]interface{}:
		for pType, value := range p {
			switch v := value.(type) {
			case string:
				result = append(result, normalizePrincipalType(pType, v))
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						result = append(result, normalizePrincipalType(pType, s))
					}
				}
			}
		}
	}
	return result
}

func normalizePrincipalType(pType, value string) string {
	switch pType {
	case "Service":
		return "service:" + value
	case "Federated":
		return "federated:" + value
	case "AWS":
		if value != "*" && !strings.HasPrefix(value, "arn:") && len(value) == 12 {
			return fmt.Sprintf("arn:aws:iam::%s:root", value)
		}
		return value
	default:
		return value
	}
}
