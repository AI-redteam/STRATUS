package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	awsops "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/graph"
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
	pivotCmd.AddCommand(newPivotHopsCmd())
	pivotCmd.AddCommand(newPivotPathCmd())
	pivotCmd.AddCommand(newPivotCanICmd())

	root.AddCommand(pivotCmd)
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
