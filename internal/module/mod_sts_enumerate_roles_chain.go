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

// STSEnumerateRolesChainModule performs recursive role assumption chain discovery.
// Starting from the current identity, it discovers all assumable roles and then
// recursively discovers what those roles can assume, building a complete pivot graph.
type STSEnumerateRolesChainModule struct {
	factory *aws.ClientFactory
	graph   *graph.Store
}

func (m *STSEnumerateRolesChainModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.sts.enumerate-roles-chain",
		Name:        "Recursive Role Chain Discovery",
		Version:     "1.0.0",
		Description: "Performs depth-limited BFS through assumable roles starting from the current identity. Discovers the full role assumption chain by analyzing trust policies on each discovered role, building a comprehensive pivot graph of lateral movement paths.",
		Services:    []string{"sts", "iam"},
		RequiredActions: []string{
			"iam:ListRoles",
			"iam:GetRole",
		},
		RequiredResources: []string{"arn:aws:iam::*:role/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_depth", Type: "int", Default: 3, Description: "Maximum chain depth for recursive role assumption"},
			{Name: "max_roles", Type: "int", Default: 100, Description: "Maximum roles to enumerate"},
			},
		Outputs: []sdk.OutputSpec{
			{Name: "roles_enumerated", Type: "int", Description: "Total roles discovered"},
			{Name: "assumable_roles", Type: "[]string", Description: "Roles the current identity can assume"},
			{Name: "chain_depth_reached", Type: "int", Description: "Maximum chain depth reached"},
			{Name: "trust_edges", Type: "int", Description: "Trust edges added to pivot graph"},
			{Name: "chains", Type: "[]map", Description: "Discovered role assumption chains"},
		},
		GraphMutations: []sdk.GraphMutationSpec{
			{EdgeType: "can_assume", SourcePattern: "*", TargetPattern: "arn:aws:iam::*:role/*"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078/004/",
			"https://attack.mitre.org/techniques/T1550/001/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "STS", SortOrder: 1},
	}
}

func (m *STSEnumerateRolesChainModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"iam:ListRoles (paginated)",
			"iam:GetRole (per role, for trust policy)",
		},
		Confidence: 1.0,
	}
}

func (m *STSEnumerateRolesChainModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	maxDepth := ctx.InputInt("max_depth")
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would enumerate IAM roles and analyze trust policies to discover role assumption chains up to depth %d.", maxDepth),
		WouldMutate: false,
		APICalls:    []string{"iam:ListRoles", "iam:GetRole"},
	}
}

func (m *STSEnumerateRolesChainModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxDepth := ctx.InputInt("max_depth")
	if maxDepth <= 0 {
		maxDepth = 3
	}
	maxRoles := ctx.InputInt("max_roles")
	if maxRoles <= 0 {
		maxRoles = 100
	}

	// Get current caller identity
	callerARN, _, _, err := m.factory.GetCallerIdentity(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("getting caller identity: %w", err))
	}

	// Register caller as a graph node so edges referencing it never cause NaN crashes
	if m.graph != nil {
		m.graph.AddNode(callerARN, "iam_principal", callerARN, ctx.Session.UUID, nil)
	}

	// Enumerate all roles
	roles, err := m.factory.ListIAMRoles(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing roles: %w", err))
	}
	if len(roles) > maxRoles {
		roles = roles[:maxRoles]
	}

	prog.Total(len(roles))

	// Phase 1: Analyze trust policies and find directly assumable roles
	trustEdges := 0
	var assumableRoles []string
	roleDetails := make(map[string]*aws.IAMRoleDetail)

	for i, role := range roles {
		prog.Update(i+1, "Analyzing trust: "+role.RoleName)

		detail, err := m.factory.GetIAMRoleDetail(bgCtx, creds, role.RoleName)
		if err != nil {
			continue
		}
		roleDetails[role.ARN] = detail

		if detail.AssumeRolePolicyDoc != "" {
			if m.graph != nil {
				m.graph.AddNode(role.ARN, "iam_role", role.RoleName, ctx.Session.UUID, map[string]any{
					"role_id": role.RoleID,
				})
			}

			// Parse trust policy and check if current identity can assume
			canAssume, principals := m.analyzeTrustPolicy(detail.AssumeRolePolicyDoc, callerARN)
			if canAssume {
				assumableRoles = append(assumableRoles, role.ARN)
			}

			// Add graph edges for all trust relationships
			for _, principal := range principals {
				if m.graph != nil {
					nodeType := "iam_principal"
					nodeLabel := principal
					if strings.HasPrefix(principal, "service:") {
						nodeType = "service"
						nodeLabel = strings.TrimPrefix(principal, "service:")
					} else if strings.HasPrefix(principal, "federated:") {
						nodeType = "federated"
						nodeLabel = strings.TrimPrefix(principal, "federated:")
					} else if strings.HasSuffix(principal, ":root") {
						nodeType = "account_root"
					}
					m.graph.AddNode(principal, nodeType, nodeLabel, ctx.Session.UUID, nil)

					edge := core.GraphEdge{
						SourceNodeID:            principal,
						TargetNodeID:            role.ARN,
						EdgeType:                core.EdgeCanAssume,
						APICallsUsed:            []string{"iam:GetRole"},
						DiscoveredBySessionUUID: ctx.Session.UUID,
						DiscoveredAt:            time.Now().UTC(),
						Confidence:              0.90,
					}
					if _, err := m.graph.AddEdge(edge); err == nil {
						trustEdges++
					}
				}
			}
		}
	}

	// Phase 2: Build chains via BFS
	var chains []map[string]any
	maxDepthReached := 0

	type chainEntry struct {
		roleARN string
		path    []string
		depth   int
	}

	visited := make(map[string]bool)
	visited[callerARN] = true

	queue := make([]chainEntry, 0)
	for _, roleARN := range assumableRoles {
		queue = append(queue, chainEntry{
			roleARN: roleARN,
			path:    []string{callerARN, roleARN},
			depth:   1,
		})
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.roleARN] {
			continue
		}
		visited[current.roleARN] = true

		if current.depth > maxDepthReached {
			maxDepthReached = current.depth
		}

		chains = append(chains, map[string]any{
			"target_role": current.roleARN,
			"path":        current.path,
			"depth":       current.depth,
		})

		// Don't recurse beyond max depth
		if current.depth >= maxDepth {
			continue
		}

		// Check what this role can assume by looking at trust policies
		for _, role := range roles {
			if visited[role.ARN] {
				continue
			}
			detail := roleDetails[role.ARN]
			if detail == nil {
				continue
			}
			canAssume, _ := m.analyzeTrustPolicy(detail.AssumeRolePolicyDoc, current.roleARN)
			if canAssume {
				newPath := make([]string, len(current.path))
				copy(newPath, current.path)
				newPath = append(newPath, role.ARN)
				queue = append(queue, chainEntry{
					roleARN: role.ARN,
					path:    newPath,
					depth:   current.depth + 1,
				})

				// Add graph edge for the chain link
				if m.graph != nil {
					edge := core.GraphEdge{
						SourceNodeID:            current.roleARN,
						TargetNodeID:            role.ARN,
						EdgeType:                core.EdgeCanAssume,
						APICallsUsed:            []string{"iam:GetRole", "trust-policy-analysis"},
						DiscoveredBySessionUUID: ctx.Session.UUID,
						DiscoveredAt:            time.Now().UTC(),
						Confidence:              0.85,
					}
					if _, err := m.graph.AddEdge(edge); err == nil {
						trustEdges++
					}
				}
			}
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"roles_enumerated":    len(roles),
			"assumable_roles":     assumableRoles,
			"chain_depth_reached": maxDepthReached,
			"trust_edges":         trustEdges,
			"chains":              chains,
		},
	}
}

func (m *STSEnumerateRolesChainModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// analyzeTrustPolicy checks if a given ARN is allowed to assume a role
// based on its trust policy. Returns whether the ARN can assume and all principals.
func (m *STSEnumerateRolesChainModule) analyzeTrustPolicy(policyDoc, callerARN string) (canAssume bool, allPrincipals []string) {
	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		decoded = policyDoc
	}

	var doc struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return false, nil
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		// Check if action includes sts:AssumeRole
		if !hasAssumeRoleAction(stmt.Action) {
			continue
		}

		principals := extractStmtPrincipals(stmt.Principal)
		allPrincipals = append(allPrincipals, principals...)

		for _, p := range principals {
			if principalMatchesARN(p, callerARN) {
				canAssume = true
			}
		}
	}

	return canAssume, allPrincipals
}

// hasAssumeRoleAction checks if the Action field includes any STS assume action.
func hasAssumeRoleAction(action interface{}) bool {
	switch a := action.(type) {
	case string:
		return isAssumeAction(a)
	case []interface{}:
		for _, item := range a {
			if s, ok := item.(string); ok && isAssumeAction(s) {
				return true
			}
		}
	}
	return false
}

func isAssumeAction(s string) bool {
	return s == "sts:AssumeRole" || s == "sts:AssumeRoleWithSAML" ||
		s == "sts:AssumeRoleWithWebIdentity" || s == "sts:*" || s == "*"
}

// principalMatchesARN checks if a trust policy principal matches a caller ARN.
func principalMatchesARN(principal, callerARN string) bool {
	if principal == "*" {
		return true
	}
	if principal == callerARN {
		return true
	}
	// Check account-level trust (arn:aws:iam::ACCOUNT:root)
	if strings.HasSuffix(principal, ":root") {
		// Extract account from the caller ARN
		parts := strings.Split(callerARN, ":")
		principalParts := strings.Split(principal, ":")
		if len(parts) >= 5 && len(principalParts) >= 5 {
			return parts[4] == principalParts[4]
		}
	}
	return false
}
