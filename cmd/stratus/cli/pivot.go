package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
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
	graphCmd.AddCommand(newPivotGraphSnapshotCmd())
	graphCmd.AddCommand(newPivotGraphStatsCmd())

	pivotCmd.AddCommand(graphCmd)
	pivotCmd.AddCommand(newPivotHopsCmd())
	pivotCmd.AddCommand(newPivotPathCmd())
	pivotCmd.AddCommand(newPivotCanICmd())

	root.AddCommand(pivotCmd)
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
			for i, edge := range path {
				fmt.Printf("  [%s] --%s--> [%s]", current, edge.EdgeType, edge.TargetNodeID)
				if len(edge.Constraints) > 0 {
					fmt.Printf("  (constraints: %v)", edge.Constraints)
				}
				fmt.Println()
				current = edge.TargetNodeID
				_ = i
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
			fmt.Printf("Evaluating: %s on %s\n", args[0], args[1])
			fmt.Println("(Full policy evaluation requires graph build. This is a best-effort check.)")
			fmt.Println("Status: UNKNOWN — run 'stratus pivot graph build' first")
			return nil
		},
	}
}
