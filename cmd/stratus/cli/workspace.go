package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/config"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/db"
	"golang.org/x/term"
)

// RegisterWorkspaceCommands adds workspace management commands to the root.
func RegisterWorkspaceCommands(root *cobra.Command) {
	wsCmd := &cobra.Command{
		Use:     "workspace",
		Aliases: []string{"ws"},
		Short:   "Manage engagement workspaces",
	}

	wsCmd.AddCommand(newWorkspaceNewCmd())
	wsCmd.AddCommand(newWorkspaceListCmd())
	wsCmd.AddCommand(newWorkspaceUseCmd())
	wsCmd.AddCommand(newWorkspaceInfoCmd())

	root.AddCommand(wsCmd)
}

func newWorkspaceNewCmd() *cobra.Command {
	var (
		name           string
		description    string
		scopeAccounts  string
		scopeRegions   string
		scopePartition string
	)

	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new engagement workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			// Prompt for passphrase
			fmt.Fprint(os.Stderr, "Enter vault passphrase: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("reading passphrase: %w", err)
			}
			fmt.Fprintln(os.Stderr)

			fmt.Fprint(os.Stderr, "Confirm passphrase: ")
			confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("reading confirmation: %w", err)
			}
			fmt.Fprintln(os.Stderr)

			if string(passBytes) != string(confirmBytes) {
				return fmt.Errorf("passphrases do not match")
			}
			passphrase := string(passBytes)
			if len(passphrase) < 8 {
				return fmt.Errorf("passphrase must be at least 8 characters")
			}

			// Build scope
			scope := core.Scope{
				Partition: scopePartition,
			}
			if scopeAccounts != "" {
				scope.AccountIDs = strings.Split(scopeAccounts, ",")
			}
			if scopeRegions != "" {
				scope.Regions = strings.Split(scopeRegions, ",")
			}

			cfg, err := config.LoadGlobalConfig()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			engine, err := core.InitWorkspace(cfg.WorkspacesDir, name, description, passphrase, scope)
			if err != nil {
				return fmt.Errorf("creating workspace: %w", err)
			}
			defer engine.Close()

			// Update global config with active workspace
			cfg.ActiveWorkspace = engine.Workspace.UUID
			if err := config.SaveGlobalConfig(cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Workspace created successfully.\n")
			fmt.Printf("  UUID: %s\n", engine.Workspace.UUID)
			fmt.Printf("  Name: %s\n", engine.Workspace.Name)
			fmt.Printf("  Path: %s\n", engine.Workspace.Path)
			if len(scope.AccountIDs) > 0 {
				fmt.Printf("  Scope accounts: %s\n", strings.Join(scope.AccountIDs, ", "))
			}
			if len(scope.Regions) > 0 {
				fmt.Printf("  Scope regions: %s\n", strings.Join(scope.Regions, ", "))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Workspace name (required)")
	cmd.Flags().StringVar(&description, "description", "", "Workspace description")
	cmd.Flags().StringVar(&scopeAccounts, "scope-accounts", "", "Comma-separated AWS account IDs in scope")
	cmd.Flags().StringVar(&scopeRegions, "scope-regions", "", "Comma-separated AWS regions in scope")
	cmd.Flags().StringVar(&scopePartition, "scope-partition", "aws", "AWS partition (aws, aws-cn, aws-us-gov)")

	return cmd
}

func newWorkspaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadGlobalConfig()
			if err != nil {
				return err
			}

			// Open the index database
			indexDB, err := db.OpenMetadataDB(cfg.WorkspacesDir)
			if err != nil {
				// No workspaces yet
				fmt.Println("No workspaces found. Create one with: stratus workspace new --name <name>")
				return nil
			}
			defer indexDB.Close()

			workspaces, err := core.ListWorkspaces(indexDB)
			if err != nil {
				return err
			}

			if len(workspaces) == 0 {
				fmt.Println("No workspaces found. Create one with: stratus workspace new --name <name>")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tNAME\tOWNER\tACCOUNTS\tCREATED")
			for _, ws := range workspaces {
				active := ""
				if ws.UUID == cfg.ActiveWorkspace {
					active = " *"
				}
				accounts := strings.Join(ws.ScopeConfig.AccountIDs, ",")
				if accounts == "" {
					accounts = "(any)"
				}
				fmt.Fprintf(w, "%s\t%s%s\t%s\t%s\t%s\n",
					ws.UUID[:8],
					ws.Name, active,
					ws.Owner,
					accounts,
					ws.CreatedAt.Format("2006-01-02"),
				)
			}
			w.Flush()

			return nil
		},
	}
}

func newWorkspaceUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name|uuid>",
		Short: "Switch to a workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadGlobalConfig()
			if err != nil {
				return err
			}

			indexDB, err := db.OpenMetadataDB(cfg.WorkspacesDir)
			if err != nil {
				return fmt.Errorf("no workspaces found")
			}
			defer indexDB.Close()

			ws, err := core.LoadWorkspaceRecord(indexDB, args[0])
			if err != nil {
				return err
			}

			cfg.ActiveWorkspace = ws.UUID
			if err := config.SaveGlobalConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("Switched to workspace: %s (%s)\n", ws.Name, ws.UUID[:8])
			return nil
		},
	}
}

func newWorkspaceInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show current workspace details",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadGlobalConfig()
			if err != nil {
				return err
			}

			if cfg.ActiveWorkspace == "" {
				return fmt.Errorf("no active workspace; use 'stratus workspace use <name>'")
			}

			indexDB, err := db.OpenMetadataDB(cfg.WorkspacesDir)
			if err != nil {
				return err
			}
			defer indexDB.Close()

			ws, err := core.LoadWorkspaceRecord(indexDB, cfg.ActiveWorkspace)
			if err != nil {
				return err
			}

			fmt.Printf("Workspace: %s\n", ws.Name)
			fmt.Printf("  UUID:        %s\n", ws.UUID)
			fmt.Printf("  Description: %s\n", ws.Description)
			fmt.Printf("  Owner:       %s\n", ws.Owner)
			fmt.Printf("  Created:     %s\n", ws.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("  Updated:     %s\n", ws.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("  Path:        %s\n", ws.Path)
			fmt.Printf("  Scope:\n")
			if len(ws.ScopeConfig.AccountIDs) > 0 {
				fmt.Printf("    Accounts: %s\n", strings.Join(ws.ScopeConfig.AccountIDs, ", "))
			} else {
				fmt.Printf("    Accounts: (unrestricted)\n")
			}
			if len(ws.ScopeConfig.Regions) > 0 {
				fmt.Printf("    Regions:  %s\n", strings.Join(ws.ScopeConfig.Regions, ", "))
			} else {
				fmt.Printf("    Regions:  (unrestricted)\n")
			}
			fmt.Printf("    Partition: %s\n", ws.ScopeConfig.Partition)

			return nil
		},
	}
}
