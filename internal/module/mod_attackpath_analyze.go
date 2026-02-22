package module

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/stratus-framework/stratus/internal/graph"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// AttackPathAnalyzerModule correlates graph edges and module run outputs to
// identify ranked attack chains from the current identity to high-value targets.
// This module makes zero AWS API calls — it reads only from local SQLite.
type AttackPathAnalyzerModule struct {
	db    *sql.DB
	graph *graph.Store
}

func (m *AttackPathAnalyzerModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.attackpath.analyze",
		Name:        "Attack Path Analyzer",
		Version:     "1.0.0",
		Description: "Correlates pivot graph edges with privilege escalation findings from prior module runs to identify ranked attack chains. Computes reachable roles via BFS, maps privesc findings to exploitation steps, and scores chains by confidence, severity, and hop count. Makes zero AWS API calls.",
		Services:    []string{"iam", "sts"},
		RiskClass:   sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "target_pattern", Type: "string", Default: "", Description: "ARN glob to filter targets (empty = all)"},
			{Name: "max_depth", Type: "int", Default: 5, Description: "Maximum chain hops"},
			{Name: "min_severity", Type: "string", Default: "medium", Description: "Minimum finding severity to include (low, medium, high, critical)"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "attack_chains", Type: "[]map", Description: "Ranked attack chains with step-by-step detail"},
			{Name: "chain_count", Type: "int", Description: "Total chains discovered"},
			{Name: "high_value_targets", Type: "[]string", Description: "Admin role ARNs from policy-analyzer"},
			{Name: "reachable_roles", Type: "[]string", Description: "Roles accessible via can_assume edges"},
			{Name: "summary", Type: "map", Description: "Aggregate statistics"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078/004/",
			"https://attack.mitre.org/techniques/T1098/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Analysis", SortOrder: 0},
	}
}

func (m *AttackPathAnalyzerModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"(none — local analysis only)"},
		Confidence:      1.0,
	}
}

func (m *AttackPathAnalyzerModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would analyze the pivot graph and prior module run outputs to identify attack chains. No AWS API calls.",
		WouldMutate: false,
	}
}

// severityRank maps severity strings to numeric values for filtering and scoring.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// privescModuleIDs lists module IDs that produce privesc_paths output.
var privescModuleIDs = []string{
	"com.stratus.iam.policy-analyzer",
	"com.stratus.codebuild.privesc-check",
	"com.stratus.cognito.privesc-check",
	"com.stratus.sagemaker.privesc-check",
	"com.stratus.eks.privesc-check",
}

// policyAnalyzerModuleID produces admin_principals output.
const policyAnalyzerModuleID = "com.stratus.iam.policy-analyzer"

type privescFinding struct {
	PrincipalType   string   `json:"principal_type"`
	PrincipalName   string   `json:"principal_name"`
	PrincipalARN    string   `json:"principal_arn"`
	Finding         string   `json:"finding"`
	Description     string   `json:"description"`
	RequiredActions []string `json:"required_actions"`
	Severity        string   `json:"severity"`
	Reference       string   `json:"reference"`
	TargetRole      string   `json:"target_role"`
}

type attackStep struct {
	StepNumber      int      `json:"step_number"`
	Action          string   `json:"action"`
	From            string   `json:"from"`
	To              string   `json:"to"`
	Description     string   `json:"description"`
	RequiredActions []string `json:"required_actions"`
	Confidence      float64  `json:"confidence"`
	Severity        string   `json:"severity"`
}

type attackChain struct {
	Rank             int          `json:"rank"`
	Target           string       `json:"target"`
	ChainScore       float64      `json:"chain_score"`
	Steps            []attackStep `json:"steps"`
	TotalHops        int          `json:"total_hops"`
	MinConfidence    float64      `json:"min_confidence"`
	ServicesInvolved []string     `json:"services_involved"`
}

func (m *AttackPathAnalyzerModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	targetPattern := ctx.InputString("target_pattern")
	maxDepth := ctx.InputInt("max_depth")
	if maxDepth <= 0 {
		maxDepth = 5
	}
	if maxDepth > 20 {
		maxDepth = 20
	}
	minSeverity := ctx.InputString("min_severity")
	if minSeverity == "" {
		minSeverity = "medium"
	}
	minSevRank := severityRank[minSeverity]
	if minSevRank == 0 {
		minSevRank = 2 // default to medium
	}

	prog.Total(5)

	// --- Step 1: Resolve current identity's principal ARN ---
	prog.Update(1, "Resolving current identity")

	currentPrincipal := ctx.Session.SessionName
	// Look up the identity's principal_arn from the identities table
	var principalARN string
	err := m.db.QueryRow(
		"SELECT principal_arn FROM identities WHERE uuid = ? AND is_archived = 0",
		ctx.Session.IdentityUUID,
	).Scan(&principalARN)
	if err == nil && principalARN != "" {
		currentPrincipal = principalARN
	}

	// --- Step 2: BFS from current identity to find reachable roles ---
	prog.Update(2, "Computing reachable roles via graph BFS")

	edges, err := m.graph.AllEdges()
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("loading graph edges: %w", err))
	}

	// Build adjacency list
	adj := make(map[string][]graphHop)
	for _, e := range edges {
		if e.IsStale {
			continue
		}
		adj[e.SourceNodeID] = append(adj[e.SourceNodeID], graphHop{
			target:     e.TargetNodeID,
			edgeType:   string(e.EdgeType),
			confidence: e.Confidence,
		})
	}

	// BFS with depth limit
	type bfsNode struct {
		nodeID string
		depth  int
		path   []graphHop
		conf   float64
	}
	visited := make(map[string]bool)
	reachableMap := make(map[string]bfsNode) // target -> best path
	queue := []bfsNode{{nodeID: currentPrincipal, depth: 0, path: nil, conf: 1.0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.nodeID] {
			continue
		}
		visited[current.nodeID] = true

		if current.nodeID != currentPrincipal {
			reachableMap[current.nodeID] = current
		}

		if current.depth >= maxDepth {
			continue
		}

		for _, hop := range adj[current.nodeID] {
			if !visited[hop.target] {
				newPath := make([]graphHop, len(current.path)+1)
				copy(newPath, current.path)
				newPath[len(current.path)] = hop
				newConf := current.conf
				if hop.confidence < newConf {
					newConf = hop.confidence
				}
				queue = append(queue, bfsNode{
					nodeID: hop.target,
					depth:  current.depth + 1,
					path:   newPath,
					conf:   newConf,
				})
			}
		}
	}

	var reachableRoles []string
	for nodeID := range reachableMap {
		reachableRoles = append(reachableRoles, nodeID)
	}
	sort.Strings(reachableRoles)

	// --- Step 3: Load privesc findings from successful module runs ---
	prog.Update(3, "Loading privilege escalation findings")

	var allFindings []privescFinding
	var adminPrincipals []string

	for _, modID := range privescModuleIDs {
		findings, admins := m.loadPrivescFindings(modID, ctx.Session.WorkspaceUUID)
		allFindings = append(allFindings, findings...)
		if modID == policyAnalyzerModuleID {
			adminPrincipals = admins
		}
	}

	// Filter by minimum severity
	var filteredFindings []privescFinding
	for _, f := range allFindings {
		if severityRank[f.Severity] >= minSevRank {
			filteredFindings = append(filteredFindings, f)
		}
	}

	// Index findings by principal ARN for quick lookup
	findingsByPrincipal := make(map[string][]privescFinding)
	for _, f := range filteredFindings {
		findingsByPrincipal[f.PrincipalARN] = append(findingsByPrincipal[f.PrincipalARN], f)
	}

	// Build set of high-value targets (admin principals)
	adminSet := make(map[string]bool)
	for _, arn := range adminPrincipals {
		adminSet[arn] = true
	}

	// --- Step 4: Build attack chains ---
	prog.Update(4, "Building and scoring attack chains")

	var chains []attackChain

	// Strategy A: For each reachable role, check if that role has privesc findings
	// meaning we can reach a principal that CAN escalate
	for roleARN, bfs := range reachableMap {
		findings := findingsByPrincipal[roleARN]
		if len(findings) == 0 {
			continue
		}

		if targetPattern != "" && !matchARNGlob(roleARN, targetPattern) {
			continue
		}

		for _, finding := range findings {
			// Build the chain: assume hops + exploit step
			var steps []attackStep
			stepNum := 1
			services := make(map[string]bool)

			// Add assume_role steps from BFS path
			prevNode := currentPrincipal
			for _, hop := range bfs.path {
				steps = append(steps, attackStep{
					StepNumber:      stepNum,
					Action:          hop.edgeType,
					From:            prevNode,
					To:              hop.target,
					Description:     fmt.Sprintf("Traverse %s edge to %s", hop.edgeType, truncateForDisplay(hop.target)),
					RequiredActions: []string{"sts:AssumeRole"},
					Confidence:      hop.confidence,
					Severity:        "info",
				})
				services["sts"] = true
				prevNode = hop.target
				stepNum++
			}

			// Add exploit step
			target := finding.TargetRole
			if target == "" {
				target = roleARN
			}
			steps = append(steps, attackStep{
				StepNumber:      stepNum,
				Action:          "exploit_privesc",
				From:            roleARN,
				To:              target,
				Description:     finding.Description,
				RequiredActions: finding.RequiredActions,
				Confidence:      severityToConfidence(finding.Severity),
				Severity:        finding.Severity,
			})
			for _, a := range finding.RequiredActions {
				svc := extractService(a)
				if svc != "" {
					services[svc] = true
				}
			}

			// Score the chain
			score := scoreChain(steps, adminSet[target])

			var svcList []string
			for s := range services {
				svcList = append(svcList, s)
			}
			sort.Strings(svcList)

			chains = append(chains, attackChain{
				Target:           target,
				ChainScore:       score,
				Steps:            steps,
				TotalHops:        len(steps),
				MinConfidence:    bfs.conf,
				ServicesInvolved: svcList,
			})
		}
	}

	// Strategy B: Check if any privesc finding's target_role is itself reachable
	// or is an admin principal (direct escalation from current identity)
	directFindings := findingsByPrincipal[currentPrincipal]
	for _, finding := range directFindings {
		target := finding.TargetRole
		if target == "" {
			target = currentPrincipal
		}
		if targetPattern != "" && !matchARNGlob(target, targetPattern) {
			continue
		}

		services := make(map[string]bool)
		for _, a := range finding.RequiredActions {
			svc := extractService(a)
			if svc != "" {
				services[svc] = true
			}
		}

		var svcList []string
		for s := range services {
			svcList = append(svcList, s)
		}
		sort.Strings(svcList)

		steps := []attackStep{
			{
				StepNumber:      1,
				Action:          "exploit_privesc",
				From:            currentPrincipal,
				To:              target,
				Description:     finding.Description,
				RequiredActions: finding.RequiredActions,
				Confidence:      severityToConfidence(finding.Severity),
				Severity:        finding.Severity,
			},
		}

		chains = append(chains, attackChain{
			Target:           target,
			ChainScore:       scoreChain(steps, adminSet[target]),
			Steps:            steps,
			TotalHops:        1,
			MinConfidence:    severityToConfidence(finding.Severity),
			ServicesInvolved: svcList,
		})
	}

	// Strategy C: For reachable roles that are themselves admin principals
	for roleARN, bfs := range reachableMap {
		if !adminSet[roleARN] {
			continue
		}
		if targetPattern != "" && !matchARNGlob(roleARN, targetPattern) {
			continue
		}

		var steps []attackStep
		stepNum := 1
		prevNode := currentPrincipal
		for _, hop := range bfs.path {
			steps = append(steps, attackStep{
				StepNumber:      stepNum,
				Action:          hop.edgeType,
				From:            prevNode,
				To:              hop.target,
				Description:     fmt.Sprintf("Traverse %s edge to %s", hop.edgeType, truncateForDisplay(hop.target)),
				RequiredActions: []string{"sts:AssumeRole"},
				Confidence:      hop.confidence,
				Severity:        "info",
			})
			prevNode = hop.target
			stepNum++
		}

		chains = append(chains, attackChain{
			Target:           roleARN,
			ChainScore:       scoreChain(steps, true),
			Steps:            steps,
			TotalHops:        len(steps),
			MinConfidence:    bfs.conf,
			ServicesInvolved: []string{"sts"},
		})
	}

	// Deduplicate chains by target+steps signature
	chains = deduplicateChains(chains)

	// Sort by score descending, assign ranks
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].ChainScore > chains[j].ChainScore
	})
	for i := range chains {
		chains[i].Rank = i + 1
	}

	// --- Step 5: Build summary ---
	prog.Update(5, "Building summary")

	severityCounts := make(map[string]int)
	serviceSet := make(map[string]bool)
	totalHops := 0
	for _, chain := range chains {
		// Count by highest severity in chain
		maxSev := "info"
		for _, step := range chain.Steps {
			if severityRank[step.Severity] > severityRank[maxSev] {
				maxSev = step.Severity
			}
		}
		severityCounts[maxSev]++
		for _, svc := range chain.ServicesInvolved {
			serviceSet[svc] = true
		}
		totalHops += chain.TotalHops
	}

	avgLen := 0.0
	if len(chains) > 0 {
		avgLen = float64(totalHops) / float64(len(chains))
	}

	var servicesTargeted []string
	for s := range serviceSet {
		servicesTargeted = append(servicesTargeted, s)
	}
	sort.Strings(servicesTargeted)

	// Convert to output format
	chainOutputs := make([]map[string]any, len(chains))
	for i, c := range chains {
		stepOutputs := make([]map[string]any, len(c.Steps))
		for j, s := range c.Steps {
			stepOutputs[j] = map[string]any{
				"step_number":      s.StepNumber,
				"action":           s.Action,
				"from":             s.From,
				"to":               s.To,
				"description":      s.Description,
				"required_actions": s.RequiredActions,
				"confidence":       s.Confidence,
				"severity":         s.Severity,
			}
		}
		chainOutputs[i] = map[string]any{
			"rank":              c.Rank,
			"target":            c.Target,
			"chain_score":       math.Round(c.ChainScore*100) / 100,
			"steps":             stepOutputs,
			"total_hops":        c.TotalHops,
			"min_confidence":    math.Round(c.MinConfidence*100) / 100,
			"services_involved": c.ServicesInvolved,
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"attack_chains":      chainOutputs,
			"chain_count":        len(chains),
			"high_value_targets": adminPrincipals,
			"reachable_roles":    reachableRoles,
			"summary": map[string]any{
				"chains_by_severity": severityCounts,
				"services_targeted":  servicesTargeted,
				"avg_chain_length":   math.Round(avgLen*100) / 100,
				"total_findings":     len(filteredFindings),
				"graph_edges":        len(edges),
			},
		},
	}
}

func (m *AttackPathAnalyzerModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// loadPrivescFindings queries the most recent successful run of a module and
// extracts privesc_paths and admin_principals from its outputs.
func (m *AttackPathAnalyzerModule) loadPrivescFindings(moduleID, workspaceUUID string) ([]privescFinding, []string) {
	var outputsJSON sql.NullString
	err := m.db.QueryRow(
		`SELECT outputs FROM module_runs
		 WHERE module_id = ? AND workspace_uuid = ? AND status = 'success'
		 ORDER BY started_at DESC LIMIT 1`,
		moduleID, workspaceUUID,
	).Scan(&outputsJSON)
	if err != nil || !outputsJSON.Valid {
		return nil, nil
	}

	var outputs map[string]any
	if json.Unmarshal([]byte(outputsJSON.String), &outputs) != nil {
		return nil, nil
	}

	var findings []privescFinding
	if paths, ok := outputs["privesc_paths"]; ok {
		raw, _ := json.Marshal(paths)
		json.Unmarshal(raw, &findings)
	}

	var admins []string
	if ap, ok := outputs["admin_principals"]; ok {
		raw, _ := json.Marshal(ap)
		json.Unmarshal(raw, &admins)
	}

	return findings, admins
}

type graphHop struct {
	target     string
	edgeType   string
	confidence float64
}

// scoreChain computes a chain score based on step confidences, severity, and hop count.
// Formula: (confidence_product * severity_bonus) / (1 + 0.1 * hops)
func scoreChain(steps []attackStep, isAdminTarget bool) float64 {
	if len(steps) == 0 {
		return 0
	}

	confProduct := 1.0
	maxSevRank := 0
	for _, s := range steps {
		confProduct *= s.Confidence
		r := severityRank[s.Severity]
		if r > maxSevRank {
			maxSevRank = r
		}
	}

	// Severity bonus: critical=4, high=3, medium=2, low=1
	sevBonus := float64(maxSevRank)
	if isAdminTarget {
		sevBonus *= 1.5
	}

	hops := len(steps)
	return (confProduct * sevBonus) / (1.0 + 0.1*float64(hops))
}

// severityToConfidence maps severity to approximate confidence for exploit steps.
func severityToConfidence(severity string) float64 {
	switch severity {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.65
	case "low":
		return 0.40
	default:
		return 0.50
	}
}

// extractService pulls the service prefix from an IAM action string.
func extractService(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0])
	}
	return ""
}

// matchARNGlob does simple glob matching on ARNs (supports * wildcards).
// Examples: "*AdminRole*", "arn:aws:iam::123*", "*"
func matchARNGlob(arn, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return simpleGlobMatch(pattern, arn)
}

func simpleGlobMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.Contains(s, pattern)
	}

	// Split on * and check that literal parts match in order
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			// First part must match at start if pattern doesn't start with *
			return false
		}
		pos += idx + len(part)
	}
	// If pattern doesn't end with *, remaining string must be empty
	if !strings.HasSuffix(pattern, "*") && pos != len(s) {
		return false
	}
	return true
}

// truncateForDisplay shortens an ARN for step descriptions.
func truncateForDisplay(arn string) string {
	if len(arn) <= 50 {
		return arn
	}
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 {
		return ".../" + parts[len(parts)-1]
	}
	return arn[:47] + "..."
}

// deduplicateChains removes chains with the same target + same step actions.
func deduplicateChains(chains []attackChain) []attackChain {
	seen := make(map[string]bool)
	var result []attackChain
	for _, c := range chains {
		key := c.Target
		for _, s := range c.Steps {
			key += "|" + s.Action + ":" + s.From + "->" + s.To
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, c)
	}
	return result
}
