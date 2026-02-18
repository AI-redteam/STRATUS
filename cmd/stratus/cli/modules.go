package cli

import (
	"fmt"

	"github.com/spf13/cobra"
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

	// Run commands (separate from modules)
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Configure and execute a module",
	}

	root.AddCommand(runCmd)

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
			keyword := ""
			if len(args) > 0 {
				keyword = args[0]
			}

			fmt.Printf("Searching modules")
			if keyword != "" {
				fmt.Printf(" matching '%s'", keyword)
			}
			if service != "" {
				fmt.Printf(" (service: %s)", service)
			}
			if risk != "" {
				fmt.Printf(" (risk: %s)", risk)
			}
			fmt.Println()
			fmt.Println("No modules loaded. Place plugin binaries in ~/.stratus/plugins/ or workspace plugins/ directory.")
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
			fmt.Println("No modules loaded. Place plugin binaries in ~/.stratus/plugins/ or workspace plugins/ directory.")
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
			fmt.Printf("Module not found: %s\n", args[0])
			fmt.Println("No modules loaded. Place plugin binaries in ~/.stratus/plugins/ or workspace plugins/ directory.")
			return nil
		},
	}
}

func newRunsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List module run history",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			fmt.Println("No module runs recorded yet.")
			return nil
		},
	}
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

			fmt.Printf("Run not found: %s\n", args[0])
			return nil
		},
	}
}
