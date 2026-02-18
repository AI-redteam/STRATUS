package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	awsops "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/module"
)

// RegisterModuleCommands adds module management and execution commands.
func RegisterModuleCommands(root *cobra.Command) {
	modCmd := &cobra.Command{
		Use:   "modules",
		Short: "Search, inspect, and manage modules",
	}

	modCmd.AddCommand(newModuleSearchCmd())
	modCmd.AddCommand(newModuleListCmd())
	modCmd.AddCommand(newModuleInfoCmd())

	root.AddCommand(modCmd)

	// Run command
	root.AddCommand(newRunCmd())

	// Runs history commands
	runsCmd := &cobra.Command{
		Use:   "runs",
		Short: "View and manage module run history",
	}
	runsCmd.AddCommand(newRunsListCmd())
	runsCmd.AddCommand(newRunsShowCmd())

	root.AddCommand(runsCmd)
}

func newModuleSearchCmd() *cobra.Command {
	var (
		service string
		risk    string
		tag     string
	)

	cmd := &cobra.Command{
		Use:   "search [keyword]",
		Short: "Search for modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			factory := awsops.NewClientFactory(engine.Logger) // No audit for browsing modules
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			keyword := ""
			if len(args) > 0 {
				keyword = args[0]
			}

			results := reg.Search(keyword, service, risk, tag)

			if len(results) == 0 {
				fmt.Println("No modules found matching criteria.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tVERSION\tRISK\tSERVICES")
			for _, m := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					m.ID, m.Name, m.Version, m.RiskClass,
					strings.Join(m.Services, ","))
			}
			w.Flush()

			return nil
		},
	}

	cmd.Flags().StringVar(&service, "service", "", "Filter by AWS service")
	cmd.Flags().StringVar(&risk, "risk", "", "Filter by risk class (read_only, write, destructive)")
	cmd.Flags().StringVar(&tag, "tag", "", "Filter by tag")

	return cmd
}

func newModuleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all loaded modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			factory := awsops.NewClientFactory(engine.Logger) // No audit for browsing modules
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			metas := reg.List()

			if len(metas) == 0 {
				fmt.Println("No modules loaded.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tVERSION\tRISK\tSERVICES")
			for _, m := range metas {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					m.ID, m.Name, m.Version, m.RiskClass,
					strings.Join(m.Services, ","))
			}
			w.Flush()

			fmt.Printf("\n%d module(s) loaded.\n", len(metas))
			return nil
		},
	}
}

func newModuleInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <module-id>",
		Short: "Show detailed module information",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			factory := awsops.NewClientFactory(engine.Logger) // No audit for browsing modules
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			mod, ok := reg.Get(args[0])
			if !ok {
				return fmt.Errorf("module not found: %s", args[0])
			}

			meta := mod.Meta()
			fmt.Printf("Module: %s\n", meta.Name)
			fmt.Printf("  ID:          %s\n", meta.ID)
			fmt.Printf("  Version:     %s\n", meta.Version)
			fmt.Printf("  Risk Class:  %s\n", meta.RiskClass)
			fmt.Printf("  Services:    %s\n", strings.Join(meta.Services, ", "))
			fmt.Printf("  Author:      %s\n", meta.Author)
			fmt.Printf("  Description: %s\n", meta.Description)
			fmt.Println()

			if len(meta.RequiredActions) > 0 {
				fmt.Println("  Required IAM Actions:")
				for _, a := range meta.RequiredActions {
					fmt.Printf("    - %s\n", a)
				}
				fmt.Println()
			}

			if len(meta.Inputs) > 0 {
				fmt.Println("  Inputs:")
				for _, inp := range meta.Inputs {
					req := ""
					if inp.Required {
						req = " [REQUIRED]"
					}
					def := ""
					if inp.Default != nil {
						def = fmt.Sprintf(" (default: %v)", inp.Default)
					}
					fmt.Printf("    %-20s %-10s %s%s%s\n", inp.Name, inp.Type, inp.Description, def, req)
				}
				fmt.Println()
			}

			if len(meta.Outputs) > 0 {
				fmt.Println("  Outputs:")
				for _, out := range meta.Outputs {
					fmt.Printf("    %-25s %-15s %s\n", out.Name, out.Type, out.Description)
				}
				fmt.Println()
			}

			if len(meta.References) > 0 {
				fmt.Println("  References:")
				for _, ref := range meta.References {
					fmt.Printf("    - %s\n", ref)
				}
			}

			return nil
		},
	}
}

func newRunCmd() *cobra.Command {
	var (
		moduleID  string
		dryRun    bool
		preflight bool
		inputJSON string
	)

	cmd := &cobra.Command{
		Use:   "run <module-id>",
		Short: "Execute a module",
		Long: `Execute a module against the active session. Use --dry-run for preview,
--preflight to check permissions before execution.

Examples:
  stratus run com.stratus.iam.enumerate-roles
  stratus run com.stratus.iam.enumerate-roles --dry-run
  stratus run com.stratus.iam.enumerate-users --inputs '{"max_users":100}'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			moduleID = args[0]

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

			// Parse inputs
			inputs := make(map[string]any)
			if inputJSON != "" {
				if err := json.Unmarshal([]byte(inputJSON), &inputs); err != nil {
					return fmt.Errorf("parsing inputs JSON: %w", err)
				}
			}

			runner := module.NewRunner(reg, engine.MetadataDB, engine.AuditLogger, factory, gs, engine.Logger, engine.Workspace.UUID)

			cfg := module.RunConfig{
				ModuleID: moduleID,
				Inputs:   inputs,
				Session:  sess,
				Creds:    creds,
				DryRun:   dryRun,
				Operator: "local",
			}

			// Preflight only
			if preflight {
				result, err := runner.Preflight(cfg)
				if err != nil {
					return err
				}

				fmt.Printf("Preflight for: %s\n\n", moduleID)
				fmt.Printf("  Confidence: %.0f%%\n", result.Confidence*100)

				if len(result.MissingPermissions) > 0 {
					fmt.Println("  Missing Permissions:")
					for _, p := range result.MissingPermissions {
						fmt.Printf("    - %s\n", p)
					}
				} else {
					fmt.Println("  Permissions: OK (all required actions available)")
				}

				if len(result.PlannedAPICalls) > 0 {
					fmt.Println("  Planned API Calls:")
					for _, c := range result.PlannedAPICalls {
						fmt.Printf("    - %s\n", c)
					}
				}

				if len(result.Warnings) > 0 {
					fmt.Println("  Warnings:")
					for _, w := range result.Warnings {
						fmt.Printf("    - %s\n", w)
					}
				}

				return nil
			}

			// Execute
			mod, ok := reg.Get(moduleID)
			if !ok {
				return fmt.Errorf("module not found: %s", moduleID)
			}
			meta := mod.Meta()

			if dryRun {
				fmt.Printf("Dry run: %s (%s)\n", meta.Name, meta.ID)
			} else {
				fmt.Printf("Running: %s (%s)\n", meta.Name, meta.ID)
			}
			fmt.Printf("  Session: %s (%s)\n", sess.SessionName, sess.Region)
			fmt.Printf("  Risk:    %s\n\n", meta.RiskClass)

			run, err := runner.Execute(context.Background(), cfg)
			if err != nil {
				return err
			}

			fmt.Printf("Run ID: %s\n", run.UUID)
			fmt.Printf("Status: %s\n", run.Status)

			if run.CompletedAt != nil {
				duration := run.CompletedAt.Sub(run.StartedAt)
				fmt.Printf("Duration: %s\n", duration.Round(1e6))
			}

			if run.ErrorDetail != nil {
				fmt.Printf("Error: %s\n", *run.ErrorDetail)
			}

			if run.Outputs != nil {
				fmt.Println("\nOutputs:")
				outJSON, _ := json.MarshalIndent(run.Outputs, "  ", "  ")
				fmt.Printf("  %s\n", string(outJSON))
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview what the module would do without executing")
	cmd.Flags().BoolVar(&preflight, "preflight", false, "Check permissions only, do not execute")
	cmd.Flags().StringVar(&inputJSON, "inputs", "", "Module inputs as JSON object")

	return cmd
}

func newRunsListCmd() *cobra.Command {
	var (
		moduleFilter string
		statusFilter string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List module run history",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			factory := awsops.NewClientFactory(engine.Logger) // No audit for browsing modules
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			runner := module.NewRunner(reg, engine.MetadataDB, engine.AuditLogger, factory, gs, engine.Logger, engine.Workspace.UUID)
			runs, err := runner.ListRuns(moduleFilter, statusFilter)
			if err != nil {
				return err
			}

			if len(runs) == 0 {
				fmt.Println("No module runs recorded yet.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tMODULE\tSTATUS\tSTARTED\tDURATION")
			for _, r := range runs {
				duration := ""
				if r.CompletedAt != nil {
					duration = r.CompletedAt.Sub(r.StartedAt).Round(1e6).String()
				}
				uuid := r.UUID
				if len(uuid) > 8 {
					uuid = uuid[:8] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					uuid,
					r.ModuleID,
					r.Status,
					r.StartedAt.Format("2006-01-02 15:04:05"),
					duration,
				)
			}
			w.Flush()

			fmt.Printf("\n%d run(s) found.\n", len(runs))
			return nil
		},
	}

	cmd.Flags().StringVar(&moduleFilter, "module", "", "Filter by module ID")
	cmd.Flags().StringVar(&statusFilter, "status", "", "Filter by status")

	return cmd
}

func newRunsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <run-uuid>",
		Short: "Show details of a module run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			factory := awsops.NewClientFactory(engine.Logger) // No audit for browsing modules
			gs := graph.NewStore(engine.MetadataDB, engine.Workspace.UUID)
			reg := module.NewRegistry(engine.MetadataDB, engine.Logger)
			module.RegisterBuiltinModules(reg, factory, gs)

			runner := module.NewRunner(reg, engine.MetadataDB, engine.AuditLogger, factory, gs, engine.Logger, engine.Workspace.UUID)
			run, err := runner.GetRun(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Run: %s\n", run.UUID)
			fmt.Printf("  Module:    %s (v%s)\n", run.ModuleID, run.ModuleVersion)
			fmt.Printf("  Session:   %s\n", run.SessionUUID)
			fmt.Printf("  Status:    %s\n", run.Status)
			fmt.Printf("  Started:   %s\n", run.StartedAt.Format("2006-01-02 15:04:05"))

			if run.CompletedAt != nil {
				fmt.Printf("  Completed: %s\n", run.CompletedAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("  Duration:  %s\n", run.CompletedAt.Sub(run.StartedAt).Round(1e6))
			}
			if run.ErrorDetail != nil {
				fmt.Printf("  Error:     %s\n", *run.ErrorDetail)
			}

			if run.Inputs != nil && len(run.Inputs) > 0 {
				fmt.Println("\n  Inputs:")
				inJSON, _ := json.MarshalIndent(run.Inputs, "    ", "  ")
				fmt.Printf("    %s\n", string(inJSON))
			}

			if run.Outputs != nil && len(run.Outputs) > 0 {
				fmt.Println("\n  Outputs:")
				outJSON, _ := json.MarshalIndent(run.Outputs, "    ", "  ")
				fmt.Printf("    %s\n", string(outJSON))
			}

			return nil
		},
	}
}
