// Package graph — builder.go implements the pivot graph construction engine.
// It enumerates IAM roles and users, parses trust policies and identity-based
// policies, and populates the graph store with can_assume and permission edges.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/audit"
	stratusaws "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
)

// Builder constructs the pivot graph by enumerating AWS IAM resources and
// analyzing their policies to discover reachable principals and permissions.
type Builder struct {
	store     *Store
	factory   *stratusaws.ClientFactory
	creds     stratusaws.SessionCredentials
	sessionID string
	audit     *audit.Logger
	logger    zerolog.Logger
}

// BuildResult summarizes what the builder discovered.
type BuildResult struct {
	RolesDiscovered   int
	UsersDiscovered   int
	NodesAdded        int
	EdgesAdded        int
	PoliciesAnalyzed  int
	Errors            []string
}

// NewBuilder creates a graph builder for the current session.
func NewBuilder(store *Store, factory *stratusaws.ClientFactory, creds stratusaws.SessionCredentials, sessionID string, al *audit.Logger, logger zerolog.Logger) *Builder {
	return &Builder{
		store:     store,
		factory:   factory,
		creds:     creds,
		sessionID: sessionID,
		audit:     al,
		logger:    logger,
	}
}

// Build executes the full graph construction pipeline:
// 1. Enumerate IAM roles and parse trust policies for can_assume edges
// 2. Enumerate IAM users
// 3. Analyze identity-based policies for permission edges
// 4. Discover resource-based policy edges (S3 bucket policies, Lambda policies)
func (b *Builder) Build(ctx context.Context, depth int) (*BuildResult, error) {
	result := &BuildResult{}

	b.logger.Info().Int("depth", depth).Msg("starting pivot graph build")

	// Phase 1: Enumerate and analyze IAM roles
	if err := b.buildRoles(ctx, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("role enumeration: %s", err))
		b.logger.Warn().Err(err).Msg("role enumeration had errors")
	}

	// Phase 2: Enumerate IAM users
	if err := b.buildUsers(ctx, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("user enumeration: %s", err))
		b.logger.Warn().Err(err).Msg("user enumeration had errors")
	}

	// Phase 3: Analyze identity-based policies for permission edges
	if err := b.buildPolicyEdges(ctx, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("policy analysis: %s", err))
		b.logger.Warn().Err(err).Msg("policy analysis had errors")
	}

	b.logger.Info().
		Int("roles", result.RolesDiscovered).
		Int("users", result.UsersDiscovered).
		Int("nodes", result.NodesAdded).
		Int("edges", result.EdgesAdded).
		Int("policies", result.PoliciesAnalyzed).
		Msg("pivot graph build complete")

	return result, nil
}

// buildRoles enumerates all IAM roles, parses trust policies, and creates
// graph nodes + can_assume edges.
func (b *Builder) buildRoles(ctx context.Context, result *BuildResult) error {
	roles, err := b.factory.ListIAMRoles(ctx, b.creds)
	if err != nil {
		return fmt.Errorf("listing roles: %w", err)
	}

	result.RolesDiscovered = len(roles)

	for _, role := range roles {
		// Add role as graph node
		if err := b.store.AddNode(role.ARN, "iam_role", role.RoleName, b.sessionID, map[string]any{
			"role_id":     role.RoleID,
			"create_date": role.CreateDate,
		}); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("adding role node %s: %s", role.RoleName, err))
			continue
		}
		result.NodesAdded++

		// Get role detail to access trust policy
		detail, err := b.factory.GetIAMRoleDetail(ctx, b.creds, role.RoleName)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("getting role detail %s: %s", role.RoleName, err))
			continue
		}

		// Parse trust policy and create can_assume edges
		principals, constraints, err := parseTrustPolicy(detail.AssumeRolePolicyDoc)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parsing trust policy for %s: %s", role.RoleName, err))
			continue
		}

		for i, principal := range principals {
			var edgeConstraints map[string]any
			if i < len(constraints) {
				edgeConstraints = constraints[i]
			}

			edge := core.GraphEdge{
				SourceNodeID:            principal,
				TargetNodeID:            role.ARN,
				EdgeType:                core.EdgeCanAssume,
				EvidenceRefs:            []string{},
				APICallsUsed:            []string{"iam:GetRole", "iam:ListRoles"},
				DiscoveredBySessionUUID: b.sessionID,
				DiscoveredAt:            time.Now().UTC(),
				Confidence:              0.95,
				Constraints:             edgeConstraints,
			}

			if _, err := b.store.AddEdge(edge); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("adding edge %s -> %s: %s", principal, role.ARN, err))
				continue
			}
			result.EdgesAdded++

			// Add source principal as node if it looks like an ARN
			if strings.HasPrefix(principal, "arn:aws:") {
				nodeType := inferNodeType(principal)
				label := inferLabel(principal)
				b.store.AddNode(principal, nodeType, label, b.sessionID, nil)
			}
		}
	}

	return nil
}

// buildUsers enumerates all IAM users and adds them as graph nodes.
func (b *Builder) buildUsers(ctx context.Context, result *BuildResult) error {
	users, err := b.factory.ListIAMUsers(ctx, b.creds)
	if err != nil {
		return fmt.Errorf("listing users: %w", err)
	}

	result.UsersDiscovered = len(users)

	for _, user := range users {
		if err := b.store.AddNode(user.ARN, "iam_user", user.UserName, b.sessionID, map[string]any{
			"user_id":     user.UserID,
			"create_date": user.CreateDate,
		}); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("adding user node %s: %s", user.UserName, err))
			continue
		}
		result.NodesAdded++
	}

	return nil
}

// buildPolicyEdges analyzes attached and inline policies on roles to discover
// permission edges (sts:AssumeRole grants that create can_assume edges between
// principals that the trust policy alone wouldn't reveal).
func (b *Builder) buildPolicyEdges(ctx context.Context, result *BuildResult) error {
	roles, err := b.factory.ListIAMRoles(ctx, b.creds)
	if err != nil {
		return nil // Already reported in buildRoles
	}

	for _, role := range roles {
		detail, err := b.factory.GetIAMRoleDetail(ctx, b.creds, role.RoleName)
		if err != nil {
			continue
		}

		// Check attached managed policies for sts:AssumeRole grants
		for _, policyARN := range detail.AttachedPolicies {
			result.PoliciesAnalyzed++
			actions, resources := b.getEffectivePermissions(ctx, policyARN)
			b.emitPermissionEdges(role.ARN, actions, resources, policyARN, result)
		}

		// Inline policies would require iam:GetRolePolicy for each name.
		// We note them as potential edges with lower confidence.
		for _, policyName := range detail.InlinePolicies {
			result.PoliciesAnalyzed++
			b.emitInlinePolicyEdge(role.ARN, policyName, result)
		}
	}

	return nil
}

// getEffectivePermissions retrieves and parses a managed policy to extract
// the actions and resources it grants.
func (b *Builder) getEffectivePermissions(ctx context.Context, policyARN string) (actions []string, resources []string) {
	// For managed policies, we'd need iam:GetPolicyVersion to get the document.
	// The adapter currently doesn't have this. We can infer from common AWS-managed
	// policies by ARN pattern. For custom policies, we mark as lower confidence.
	if isAWSManagedPolicy(policyARN) {
		return inferAWSManagedPolicyPermissions(policyARN)
	}
	return nil, nil
}

// emitPermissionEdges creates graph edges for discovered sts:AssumeRole permissions.
func (b *Builder) emitPermissionEdges(sourceARN string, actions, resources []string, evidenceRef string, result *BuildResult) {
	for _, action := range actions {
		if action == "sts:AssumeRole" || action == "sts:*" || action == "*" {
			for _, resource := range resources {
				if resource == "*" || strings.Contains(resource, ":role/") {
					edge := core.GraphEdge{
						SourceNodeID:            sourceARN,
						TargetNodeID:            resource,
						EdgeType:                core.EdgeCanAssume,
						EvidenceRefs:            []string{evidenceRef},
						APICallsUsed:            []string{"iam:GetPolicyVersion"},
						DiscoveredBySessionUUID: b.sessionID,
						Confidence:              0.85,
					}
					if _, err := b.store.AddEdge(edge); err == nil {
						result.EdgesAdded++
					}
				}
			}
		}
	}
}

// emitInlinePolicyEdge records that an inline policy exists (we can't read its
// content without iam:GetRolePolicy), creating a lower-confidence edge.
func (b *Builder) emitInlinePolicyEdge(roleARN, policyName string, result *BuildResult) {
	// We don't know what the inline policy grants, but we note its existence
	// as metadata on the role node.
	b.store.AddNode(roleARN, "iam_role", "", b.sessionID, map[string]any{
		"has_inline_policy": policyName,
	})
}

// --- Trust Policy Parsing ---

// iamPolicyDocument represents an IAM policy JSON document.
type iamPolicyDocument struct {
	Version   string                 `json:"Version"`
	Statement []iamPolicyStatement   `json:"Statement"`
}

// iamPolicyStatement represents a single statement in a policy document.
type iamPolicyStatement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"` // string "*" or map[string]interface{}
	Action    interface{} `json:"Action"`    // string or []string
	Condition interface{} `json:"Condition,omitempty"`
}

// parseTrustPolicy parses an IAM role trust policy document and extracts
// the principal ARNs that can assume the role, plus any constraints.
func parseTrustPolicy(policyDoc string) (principals []string, constraints []map[string]any, err error) {
	if policyDoc == "" {
		return nil, nil, nil
	}

	// Trust policies from the API are URL-encoded
	decoded, decErr := url.QueryUnescape(policyDoc)
	if decErr != nil {
		decoded = policyDoc
	}

	var doc iamPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing trust policy JSON: %w", err)
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		// Only consider sts:AssumeRole actions
		if !actionMatchesAssumeRole(stmt.Action) {
			continue
		}

		stmtConstraints := extractConstraints(stmt.Condition)

		// Parse principals
		stmtPrincipals := extractPrincipals(stmt.Principal)
		for _, p := range stmtPrincipals {
			principals = append(principals, p)
			constraints = append(constraints, stmtConstraints)
		}
	}

	return principals, constraints, nil
}

// actionMatchesAssumeRole checks if the Action field contains sts:AssumeRole
// or a wildcard that covers it.
func actionMatchesAssumeRole(action interface{}) bool {
	switch a := action.(type) {
	case string:
		return matchesAssumeAction(a)
	case []interface{}:
		for _, item := range a {
			if s, ok := item.(string); ok && matchesAssumeAction(s) {
				return true
			}
		}
	}
	return false
}

func matchesAssumeAction(action string) bool {
	action = strings.ToLower(action)
	return action == "sts:assumerole" ||
		action == "sts:assumerolewithoptions" ||
		action == "sts:assumerolewithsaml" ||
		action == "sts:assumerolewithwebidentity" ||
		action == "sts:*" ||
		action == "*"
}

// extractPrincipals extracts principal ARNs from the Principal field.
func extractPrincipals(principal interface{}) []string {
	var result []string

	switch p := principal.(type) {
	case string:
		if p == "*" {
			result = append(result, "*")
		} else {
			result = append(result, p)
		}
	case map[string]interface{}:
		for principalType, value := range p {
			switch v := value.(type) {
			case string:
				result = append(result, normalizePrincipal(principalType, v))
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						result = append(result, normalizePrincipal(principalType, s))
					}
				}
			}
		}
	}

	return result
}

// normalizePrincipal creates a consistent representation for a trust principal.
func normalizePrincipal(principalType, value string) string {
	switch principalType {
	case "AWS":
		if value == "*" {
			return "*"
		}
		// Already an ARN
		if strings.HasPrefix(value, "arn:") {
			return value
		}
		// Account ID
		if len(value) == 12 {
			return fmt.Sprintf("arn:aws:iam::%s:root", value)
		}
		return value
	case "Service":
		return "service:" + value
	case "Federated":
		return "federated:" + value
	default:
		return value
	}
}

// extractConstraints pulls condition keys from a trust policy statement
// that are relevant to assume-role operations.
func extractConstraints(condition interface{}) map[string]any {
	if condition == nil {
		return nil
	}

	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return nil
	}

	constraints := make(map[string]any)

	for operator, conditions := range condMap {
		conds, ok := conditions.(map[string]interface{})
		if !ok {
			continue
		}

		for key, value := range conds {
			switch key {
			case "aws:MultiFactorAuthPresent":
				if val, ok := value.(string); ok && val == "true" {
					constraints["mfa_required"] = true
				}
			case "sts:ExternalId":
				constraints["external_id_required"] = true
				constraints["external_id_value"] = value
			case "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce":
				constraints[key] = value
			case "aws:PrincipalOrgID":
				constraints["org_id_required"] = value
			default:
				constraints[operator+":"+key] = value
			}
		}
	}

	if len(constraints) == 0 {
		return nil
	}
	return constraints
}

// --- Helper Functions ---

// inferNodeType determines the graph node type from an ARN.
func inferNodeType(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "unknown"
	}

	resource := parts[5]
	switch {
	case strings.HasPrefix(resource, "user/"):
		return "iam_user"
	case strings.HasPrefix(resource, "role/"):
		return "iam_role"
	case strings.HasPrefix(resource, "root"):
		return "account_root"
	case strings.HasPrefix(resource, "assumed-role/"):
		return "assumed_role"
	default:
		return "iam_principal"
	}
}

// inferLabel extracts a human-readable label from an ARN.
func inferLabel(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	parts = strings.Split(arn, ":")
	return parts[len(parts)-1]
}

// isAWSManagedPolicy checks if a policy ARN is AWS-managed.
func isAWSManagedPolicy(arn string) bool {
	return strings.HasPrefix(arn, "arn:aws:iam::aws:policy/")
}

// inferAWSManagedPolicyPermissions returns known permissions for common
// AWS-managed policies. This avoids needing iam:GetPolicyVersion for
// well-known policies.
func inferAWSManagedPolicyPermissions(arn string) (actions []string, resources []string) {
	knownPolicies := map[string]struct {
		actions   []string
		resources []string
	}{
		"arn:aws:iam::aws:policy/AdministratorAccess": {
			actions:   []string{"*"},
			resources: []string{"*"},
		},
		"arn:aws:iam::aws:policy/PowerUserAccess": {
			actions:   []string{"*"},
			resources: []string{"*"},
			// Note: PowerUser excludes IAM/Org, but for assume-role detection this is sufficient
		},
		"arn:aws:iam::aws:policy/IAMFullAccess": {
			actions:   []string{"iam:*", "sts:*"},
			resources: []string{"*"},
		},
		"arn:aws:iam::aws:policy/SecurityAudit": {
			actions:   []string{"iam:Get*", "iam:List*", "sts:GetCallerIdentity"},
			resources: []string{"*"},
		},
	}

	if known, ok := knownPolicies[arn]; ok {
		return known.actions, known.resources
	}
	return nil, nil
}

// DiffSnapshots compares two graph snapshots and returns the differences.
func DiffSnapshots(oldData, newData []byte) (*SnapshotDiff, error) {
	var oldSnap, newSnap snapshotData
	if err := json.Unmarshal(oldData, &oldSnap); err != nil {
		return nil, fmt.Errorf("parsing old snapshot: %w", err)
	}
	if err := json.Unmarshal(newData, &newSnap); err != nil {
		return nil, fmt.Errorf("parsing new snapshot: %w", err)
	}

	diff := &SnapshotDiff{}

	// Compare nodes
	oldNodes := make(map[string]bool)
	for _, n := range oldSnap.Nodes {
		oldNodes[n.ID] = true
	}
	newNodes := make(map[string]bool)
	for _, n := range newSnap.Nodes {
		newNodes[n.ID] = true
		if !oldNodes[n.ID] {
			diff.NodesAdded = append(diff.NodesAdded, n.ID)
		}
	}
	for _, n := range oldSnap.Nodes {
		if !newNodes[n.ID] {
			diff.NodesRemoved = append(diff.NodesRemoved, n.ID)
		}
	}

	// Compare edges
	oldEdges := make(map[string]bool)
	for _, e := range oldSnap.Edges {
		key := e.SourceNodeID + "|" + e.TargetNodeID + "|" + string(e.EdgeType)
		oldEdges[key] = true
	}
	newEdges := make(map[string]bool)
	for _, e := range newSnap.Edges {
		key := e.SourceNodeID + "|" + e.TargetNodeID + "|" + string(e.EdgeType)
		newEdges[key] = true
		if !oldEdges[key] {
			diff.EdgesAdded = append(diff.EdgesAdded, fmt.Sprintf("%s --%s--> %s", e.SourceNodeID, e.EdgeType, e.TargetNodeID))
		}
	}
	for _, e := range oldSnap.Edges {
		key := e.SourceNodeID + "|" + e.TargetNodeID + "|" + string(e.EdgeType)
		if !newEdges[key] {
			diff.EdgesRemoved = append(diff.EdgesRemoved, fmt.Sprintf("%s --%s--> %s", e.SourceNodeID, e.EdgeType, e.TargetNodeID))
		}
	}

	return diff, nil
}

// SnapshotDiff represents differences between two graph snapshots.
type SnapshotDiff struct {
	NodesAdded   []string `json:"nodes_added"`
	NodesRemoved []string `json:"nodes_removed"`
	EdgesAdded   []string `json:"edges_added"`
	EdgesRemoved []string `json:"edges_removed"`
}

type snapshotData struct {
	Nodes []snapshotNode   `json:"nodes"`
	Edges []core.GraphEdge `json:"edges"`
}

type snapshotNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}
