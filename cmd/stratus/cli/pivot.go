package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/artifact"
	awsops "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/identity"
	"github.com/stratus-framework/stratus/internal/module"
	"github.com/stratus-framework/stratus/internal/scope"
	"github.com/stratus-framework/stratus/internal/session"
)

// RegisterPivotCommands adds pivot graph and path-finding commands.
func RegisterPivotCommands(root *cobra.Command) {
	pivotCmd := &cobra.Command{
		Use:   "pivot",
		Short: "Permission intelligence and pivot planning",
	}

	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Manage the pivot graph",
	}
	graphCmd.AddCommand(newPivotGraphBuildCmd())
	graphCmd.AddCommand(newPivotGraphSnapshotCmd())
	graphCmd.AddCommand(newPivotGraphDiffCmd())
	graphCmd.AddCommand(newPivotGraphStatsCmd())

	pivotCmd.AddCommand(graphCmd)
	pivotCmd.AddCommand(newPivotAssumeCmd())
	pivotCmd.AddCommand(newPivotHopsCmd())
	pivotCmd.AddCommand(newPivotPathCmd())
	pivotCmd.AddCommand(newPivotCanICmd())
	pivotCmd.AddCommand(newPivotAttackPathsCmd())

	root.AddCommand(pivotCmd)
}

func newPivotAssumeCmd() *cobra.Command {
	var (
		externalID string
		label      string
		duration   int32
	)

	cmd := &cobra.Command{
		Use:   "assume <role-arn>",
		Short: "Assume an IAM role and push the new session onto the context stack",
		Long: `Perform STS AssumeRole using the active session's credentials, then import
the resulting temporary credentials as a new identity and push the session
onto the context stack. This is the primary mechanism for lateral movement.

Examples:
  stratus pivot assume arn:aws:iam::123456789012:role/AdminRole
  stratus pivot assume arn:aws:iam::123456789012:role/CrossAccount --external-id abc123
  stratus pivot assume arn:aws:iam::123456789012:role/ShortLived --duration 900 --label prod-admin`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			roleARN := args[0]

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			creds, sess, err := awsops.ResolveActiveCredentials(engine)
			if err != nil {
				return err
			}

			// Enforce workspace scope
			checker := scope.NewChecker(engine.Workspace.ScopeConfig)
			if err := checker.CheckRegion(creds.Region); err != nil {
				return fmt.Errorf("scope violation: %w", err)
			}
			if err := checker.CheckARN(roleARN); err != nil {
				return fmt.Errorf("scope violation: target role is out of scope: %w", err)
			}

			factory := awsops.NewClientFactoryWithAudit(engine.Logger, engine.AuditLogger, sess.UUID)

			// Generate STS session name
			sessionName := "stratus"
			if label != "" {
				sessionName = label
			}

			fmt.Printf("Assuming role: %s\n", roleARN)
			fmt.Printf("  Source session: %s (%s)\n", sess.SessionName, sess.UUID[:8])
			fmt.Printf("  Region:         %s\n", sess.Region)
			if externalID != "" {
				fmt.Printf("  External ID:    %s\n", externalID)
			}
			fmt.Printf("  Duration:       %ds\n", duration)
			fmt.Println()

			result, err := factory.AssumeRole(context.Background(), creds, roleARN, sessionName, externalID, duration)
			if err != nil {
				return err
			}

			// Derive label if not set
			if label == "" {
				label = result.AssumedRoleARN
			}

			// Import the assumed role credentials
			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)
			expiry := result.Expiration
			id, newSession, err := broker.ImportAssumedRoleSession(identity.AssumedRoleSessionInput{
				AccessKey:         result.AccessKeyID,
				SecretKey:         result.SecretAccessKey,
				SessionToken:     result.SessionToken,
				Expiry:           &expiry,
				Label:            label,
				Region:           sess.Region,
				RoleARN:          roleARN,
				ExternalID:       externalID,
				SourceSessionUUID: sess.UUID,
			})
			if err != nil {
				return fmt.Errorf("importing assumed role session: %w", err)
			}

			// Push the new session onto the context stack
			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			pushed, err := mgr.Push(newSession.UUID)
			if err != nil {
				return fmt.Errorf("pushing session to context stack: %w", err)
			}

			fmt.Printf("Role assumed successfully.\n\n")
			fmt.Printf("  Identity: %s (%s)\n", id.Label, id.UUID[:8])
			fmt.Printf("  Session:  %s (%s)\n", pushed.SessionName, pushed.UUID[:8])
			fmt.Printf("  Role ARN: %s\n", result.AssumedRoleARN)
			fmt.Printf("  Region:   %s\n", pushed.Region)
			if pushed.Expiry != nil {
				fmt.Printf("  Expiry:   %s (%dm remaining)\n",
					pushed.Expiry.Format(time.RFC3339),
					int(time.Until(*pushed.Expiry).Minutes()),
				)
			}
			fmt.Printf("\nSession is now active. Use 'stratus sessions pop' to revert.\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&externalID, "external-id", "", "External ID for cross-account role assumption")
	cmd.Flags().StringVar(&label, "label", "", "Label for the new session (default: assumed role ARN)")
	cmd.Flags().Int32Var(&duration, "duration", 3600, "Session duration in seconds (900-43200)")

	return cmd
}

func newPivotGraphBuildCmd() *cobra.Command {
	var depth int

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the pivot graph by enumerating IAM roles, users, and policies",
		Long: `Enumerates IAM roles and users in the target account, parses trust policies
to discover can_assume edges, and analyzes identity-based policies for
permission relationships. Results populate the workspace pivot graph.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			creds, sess, err := awsops.ResolveActiveCredentials(engine)
			if err != nil {
				return err
			}

			// Enforce workspace scope
			checker := scope.NewChecker(engine.Workspace.ScopeConfig)
			if err := checker.CheckRegion(creds.Region); err != nil {
				return fmt.Errorf("scope violation: %w", err)
			}

			factory := awsops.NewClientFactoryWithAudit(engine.Logger, engine.AuditLogger, sess.UUID)
			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			builder := graph.NewBuilder(store, factory, creds, sess.UUID, engine.AuditLogger, engine.Logger)

			fmt.Println("Building pivot graph...")
			fmt.Printf("  Session:  %s (%s)\n", sess.SessionName, sess.AWSAccessKeyID)
			fmt.Printf("  Region:   %s\n", sess.Region)
			fmt.Printf("  Depth:    %d\n", depth)
			fmt.Println()

			result, err := builder.Build(context.Background(), depth)
			if err != nil {
				return fmt.Errorf("graph build failed: %w", err)
			}

			fmt.Printf("Graph Build Results:\n")
			fmt.Printf("  Roles discovered:   %d\n", result.RolesDiscovered)
			fmt.Printf("  Users discovered:   %d\n", result.UsersDiscovered)
			fmt.Printf("  Nodes added:        %d\n", result.NodesAdded)
			fmt.Printf("  Edges added:        %d\n", result.EdgesAdded)
			fmt.Printf("  Policies analyzed:  %d\n", result.PoliciesAnalyzed)

			if len(result.Errors) > 0 {
				fmt.Printf("\n  Warnings (%d):\n", len(result.Errors))
				for _, e := range result.Errors {
					fmt.Printf("    - %s\n", e)
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&depth, "depth", 2, "Discovery depth (number of hops to traverse)")
	return cmd
}

func newPivotGraphSnapshotCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Export current graph state as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			data, err := store.Snapshot()
			if err != nil {
				return err
			}

			if output != "" {
				if err := os.WriteFile(output, data, 0644); err != nil {
					return err
				}
				fmt.Printf("Graph snapshot saved to: %s\n", output)
			} else {
				fmt.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&output, "output", "", "Output file path")
	return cmd
}

func newPivotGraphDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <snapshot1> <snapshot2>",
		Short: "Compare two graph snapshots and show differences",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldData, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading %s: %w", args[0], err)
			}
			newData, err := os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("reading %s: %w", args[1], err)
			}

			diff, err := graph.DiffSnapshots(oldData, newData)
			if err != nil {
				return err
			}

			fmt.Printf("Graph Diff: %s vs %s\n\n", args[0], args[1])

			if len(diff.NodesAdded) > 0 {
				fmt.Printf("Nodes Added (%d):\n", len(diff.NodesAdded))
				for _, n := range diff.NodesAdded {
					fmt.Printf("  + %s\n", n)
				}
				fmt.Println()
			}
			if len(diff.NodesRemoved) > 0 {
				fmt.Printf("Nodes Removed (%d):\n", len(diff.NodesRemoved))
				for _, n := range diff.NodesRemoved {
					fmt.Printf("  - %s\n", n)
				}
				fmt.Println()
			}
			if len(diff.EdgesAdded) > 0 {
				fmt.Printf("Edges Added (%d):\n", len(diff.EdgesAdded))
				for _, e := range diff.EdgesAdded {
					fmt.Printf("  + %s\n", e)
				}
				fmt.Println()
			}
			if len(diff.EdgesRemoved) > 0 {
				fmt.Printf("Edges Removed (%d):\n", len(diff.EdgesRemoved))
				for _, e := range diff.EdgesRemoved {
					fmt.Printf("  - %s\n", e)
				}
				fmt.Println()
			}

			if len(diff.NodesAdded)+len(diff.NodesRemoved)+len(diff.EdgesAdded)+len(diff.EdgesRemoved) == 0 {
				fmt.Println("No differences found.")
			}

			return nil
		},
	}
}

func newPivotGraphStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show graph statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			nodes, edges, stale, err := store.Stats()
			if err != nil {
				return err
			}

			fmt.Printf("Graph Statistics:\n")
			fmt.Printf("  Nodes:       %d\n", nodes)
			fmt.Printf("  Edges:       %d\n", edges)
			fmt.Printf("  Stale edges: %d\n", stale)

			return nil
		},
	}
}

func newPivotHopsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hops",
		Short: "List directly assumable roles from current session",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			active, err := mgr.GetActiveSession()
			if err != nil {
				return err
			}

			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)

			// Try looking up by access key ID and by principal ARN
			hops, err := store.Hops(active.AWSAccessKeyID)
			if err != nil {
				return err
			}

			if len(hops) == 0 {
				fmt.Println("No directly assumable roles found from current session.")
				fmt.Println("Run 'stratus pivot graph build' to discover pivot paths.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TARGET\tCONFIDENCE\tCONSTRAINTS")
			for _, h := range hops {
				constraints := "(none)"
				if len(h.Constraints) > 0 {
					var parts []string
					for k, v := range h.Constraints {
						parts = append(parts, fmt.Sprintf("%s=%v", k, v))
					}
					constraints = strings.Join(parts, ", ")
				}
				fmt.Fprintf(w, "%s\t%.2f\t%s\n", h.TargetNodeID, h.Confidence, constraints)
			}
			w.Flush()

			return nil
		},
	}
}

func newPivotPathCmd() *cobra.Command {
	var to string

	cmd := &cobra.Command{
		Use:   "path",
		Short: "Find shortest path to a target role/principal",
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return fmt.Errorf("--to is required (target role ARN)")
			}

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			active, err := mgr.GetActiveSession()
			if err != nil {
				return err
			}

			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			path, confidence, err := store.FindPath(active.AWSAccessKeyID, to)
			if err != nil {
				return fmt.Errorf("no path found: %w", err)
			}

			fmt.Printf("Path found (%d hops, confidence %.2f):\n", len(path), confidence)
			current := active.SessionName
			for _, edge := range path {
				fmt.Printf("  [%s] --%s--> [%s]", current, edge.EdgeType, edge.TargetNodeID)
				if len(edge.Constraints) > 0 {
					fmt.Printf("  (constraints: %v)", edge.Constraints)
				}
				fmt.Println()
				current = edge.TargetNodeID
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&to, "to", "", "Target role ARN or principal")
	return cmd
}

func newPivotCanICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "can-i <action> <resource-arn>",
		Short: "Check if current session can perform an action (best-effort local evaluation)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := args[0]
			resource := args[1]

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			active, err := mgr.GetActiveSession()
			if err != nil {
				return err
			}

			store := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)

			fmt.Printf("Evaluating: %s on %s\n", action, resource)
			fmt.Printf("  Session: %s\n\n", active.SessionName)

			// Check if this is an sts:AssumeRole action
			if strings.HasPrefix(strings.ToLower(action), "sts:assume") {
				// Check for direct can_assume edge
				hops, err := store.Hops(active.AWSAccessKeyID)
				if err == nil {
					for _, hop := range hops {
						if hop.TargetNodeID == resource {
							conf := hop.Confidence
							label := "LIKELY YES"
							if conf < 0.7 {
								label = "POSSIBLY"
							}
							fmt.Printf("Result: %s  (confidence %.2f)\n", label, conf)
							if len(hop.Constraints) > 0 {
								fmt.Printf("Constraints: %v\n", hop.Constraints)
							}
							if len(hop.EvidenceRefs) > 0 {
								fmt.Printf("Evidence: %v\n", hop.EvidenceRefs)
							}
							return nil
						}
					}
				}

				// Check for path (indirect)
				path, conf, err := store.FindPath(active.AWSAccessKeyID, resource)
				if err == nil && len(path) > 0 {
					label := "LIKELY YES (via chain)"
					if conf < 0.7 {
						label = "POSSIBLY (via chain)"
					}
					fmt.Printf("Result: %s  (%d hops, confidence %.2f)\n", label, len(path), conf)
					return nil
				}

				fmt.Println("Result: UNKNOWN — no graph edge found for this action/resource pair.")
				fmt.Println("Run 'stratus pivot graph build' to populate the graph.")
				return nil
			}

			// For non-assume actions, check graph edges
			outEdges, err := store.GetOutEdges(active.AWSAccessKeyID)
			if err == nil {
				for _, edge := range outEdges {
					if edge.TargetNodeID == resource {
						fmt.Printf("Result: LIKELY YES  (edge type: %s, confidence %.2f)\n", edge.EdgeType, edge.Confidence)
						return nil
					}
				}
			}

			fmt.Println("Result: UNKNOWN — no graph edge found for this action/resource pair.")
			fmt.Println("Tip: Run 'stratus pivot graph build' to discover permissions, or verify")
			fmt.Println("     with the AWS IAM policy simulator for high-stakes operations.")
			return nil
		},
	}
}

func newPivotAttackPathsCmd() *cobra.Command {
	var (
		target   string
		depth    int
		severity string
		asJSON   bool
	)

	cmd := &cobra.Command{
		Use:   "attack-paths",
		Short: "Analyze attack paths from current identity to high-value targets",
		Long: `Correlates pivot graph edges with privilege escalation findings from prior
module runs to identify ranked attack chains. Computes reachable roles via BFS,
maps privesc findings to exploitation steps, and scores chains by confidence,
severity, and hop count. Makes zero AWS API calls.

Prerequisites:
  1. Run 'stratus pivot graph build' to populate the pivot graph
  2. Run privesc modules (iam.policy-analyzer, codebuild.privesc-check, etc.)

Examples:
  stratus pivot attack-paths
  stratus pivot attack-paths --target "*AdminRole*"
  stratus pivot attack-paths --severity critical --depth 3
  stratus pivot attack-paths --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			creds, sess, err := awsops.ResolveActiveCredentials(engine)
			if err != nil {
				return err
			}

			factory := awsops.NewClientFactoryWithAudit(engine.Logger, engine.AuditLogger, sess.UUID)
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			// No scope enforcement — this module is local-only analysis (zero AWS API calls).
			runner := module.NewRunner(reg, engine.MetadataDB, engine.AuditLogger, factory, gs, engine.Logger, engine.Workspace.UUID)
			runner.SetArtifactStore(artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID))

			inputs := map[string]any{
				"target_pattern": target,
				"max_depth":      depth,
				"min_severity":   severity,
			}

			cfg := module.RunConfig{
				ModuleID: "com.stratus.attackpath.analyze",
				Inputs:   inputs,
				Session:  sess,
				Creds:    creds,
				Operator: "cli",
			}

			fmt.Println("Analyzing attack paths...")
			fmt.Printf("  Session:  %s (%s)\n", sess.SessionName, sess.UUID[:8])
			fmt.Printf("  Region:   %s\n", sess.Region)
			if target != "" {
				fmt.Printf("  Target:   %s\n", target)
			}
			fmt.Printf("  Depth:    %d\n", depth)
			fmt.Printf("  Severity: %s+\n", severity)
			fmt.Println()

			run, err := runner.Execute(context.Background(), cfg)
			if err != nil {
				return err
			}

			if run.ErrorDetail != nil {
				return fmt.Errorf("analysis failed: %s", *run.ErrorDetail)
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(run.Outputs)
			}

			return renderAttackPaths(run.Outputs)
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "ARN glob to filter targets")
	cmd.Flags().IntVar(&depth, "depth", 5, "Maximum chain hops")
	cmd.Flags().StringVar(&severity, "severity", "medium", "Minimum severity (low, medium, high, critical)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output raw JSON")

	return cmd
}

func renderAttackPaths(outputs map[string]any) error {
	chainCount := 0
	if v, ok := outputs["chain_count"]; ok {
		switch n := v.(type) {
		case int:
			chainCount = n
		case float64:
			chainCount = int(n)
		}
	}

	// Reachable roles
	if roles, ok := outputs["reachable_roles"].([]string); ok && len(roles) > 0 {
		fmt.Printf("Reachable Roles: %d\n", len(roles))
		for _, r := range roles {
			if len(roles) <= 10 {
				fmt.Printf("  - %s\n", r)
			}
		}
		if len(roles) > 10 {
			fmt.Printf("  (showing first 10 of %d)\n", len(roles))
			for _, r := range roles[:10] {
				fmt.Printf("  - %s\n", r)
			}
		}
		fmt.Println()
	}

	// High-value targets
	if targets, ok := outputs["high_value_targets"].([]string); ok && len(targets) > 0 {
		fmt.Printf("High-Value Targets (Admin): %d\n", len(targets))
		for _, t := range targets {
			fmt.Printf("  * %s\n", t)
		}
		fmt.Println()
	}

	if chainCount == 0 {
		fmt.Println("No attack chains found.")
		fmt.Println("\nTips:")
		fmt.Println("  - Run 'stratus pivot graph build' to populate the pivot graph")
		fmt.Println("  - Run privesc modules to discover escalation paths:")
		fmt.Println("    stratus modules run com.stratus.iam.policy-analyzer")
		fmt.Println("    stratus modules run com.stratus.codebuild.privesc-check")
		return nil
	}

	fmt.Printf("Attack Chains Found: %d\n\n", chainCount)

	chains, ok := outputs["attack_chains"].([]map[string]any)
	if !ok {
		// Handle the case where the type assertion fails (e.g., from JSON unmarshalling)
		if raw, ok2 := outputs["attack_chains"]; ok2 {
			data, _ := json.Marshal(raw)
			json.Unmarshal(data, &chains)
		}
	}

	for _, chain := range chains {
		rank := toInt(chain["rank"])
		target := toString(chain["target"])
		score := toFloat(chain["chain_score"])
		hops := toInt(chain["total_hops"])

		// Determine max severity in chain
		maxSev := "info"
		steps := toMapSlice(chain["steps"])
		for _, s := range steps {
			sev := toString(s["severity"])
			if severityRankCLI(sev) > severityRankCLI(maxSev) {
				maxSev = sev
			}
		}

		sevLabel := strings.ToUpper(maxSev)
		fmt.Printf("[%d] %s | Score: %.2f | %d hop%s -> %s\n",
			rank, sevLabel, score, hops, pluralS(hops), target)

		for _, step := range steps {
			stepNum := toInt(step["step_number"])
			action := toString(step["action"])
			desc := toString(step["description"])
			to := toString(step["to"])

			switch action {
			case "can_assume", "trust":
				fmt.Printf("    Step %d: %s %s (confidence: %.2f)\n",
					stepNum, action, to, toFloat(step["confidence"]))
			case "exploit_privesc":
				fmt.Printf("    Step %d: exploit %s\n", stepNum, to)
				fmt.Printf("            %s\n", desc)
				if actions, ok := step["required_actions"]; ok {
					actionStrs := toStringSlice(actions)
					if len(actionStrs) > 0 {
						fmt.Printf("            Required: %s\n", strings.Join(actionStrs, ", "))
					}
				}
			default:
				fmt.Printf("    Step %d: %s -> %s\n", stepNum, action, to)
			}
		}
		fmt.Println()
	}

	// Summary
	if summary, ok := outputs["summary"].(map[string]any); ok {
		fmt.Printf("Summary:\n")
		if bySev, ok := summary["chains_by_severity"].(map[string]any); ok {
			var parts []string
			for sev, count := range bySev {
				parts = append(parts, fmt.Sprintf("%s=%v", sev, count))
			}
			if len(parts) > 0 {
				fmt.Printf("  Chains by severity: %s\n", strings.Join(parts, ", "))
			}
		}
		if avg, ok := summary["avg_chain_length"]; ok {
			fmt.Printf("  Avg chain length:   %.1f\n", toFloat(avg))
		}
	}

	return nil
}

func severityRankCLI(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		var result []string
		for _, item := range s {
			result = append(result, fmt.Sprintf("%v", item))
		}
		return result
	}
	return nil
}

func toMapSlice(v any) []map[string]any {
	switch s := v.(type) {
	case []map[string]any:
		return s
	case []any:
		var result []map[string]any
		for _, item := range s {
			if m, ok := item.(map[string]any); ok {
				result = append(result, m)
			}
		}
		return result
	}
	return nil
}
