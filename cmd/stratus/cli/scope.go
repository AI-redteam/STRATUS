package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/scope"
)

// RegisterScopeCommands adds scope management commands.
func RegisterScopeCommands(root *cobra.Command) {
	scopeCmd := &cobra.Command{
		Use:   "scope",
		Short: "Manage workspace scope (blast radius)",
	}

	scopeCmd.AddCommand(newScopeShowCmd())
	scopeCmd.AddCommand(newScopeUpdateCmd())
	scopeCmd.AddCommand(newScopeCheckCmd())

	root.AddCommand(scopeCmd)
}

func newScopeShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current workspace scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			s := engine.Workspace.ScopeConfig
			fmt.Println("Workspace Scope:")
			if len(s.AccountIDs) > 0 {
				fmt.Printf("  Accounts:  %s\n", strings.Join(s.AccountIDs, ", "))
			} else {
				fmt.Printf("  Accounts:  (unrestricted)\n")
			}
			if len(s.Regions) > 0 {
				fmt.Printf("  Regions:   %s\n", strings.Join(s.Regions, ", "))
			} else {
				fmt.Printf("  Regions:   (unrestricted)\n")
			}
			fmt.Printf("  Partition: %s\n", s.Partition)
			if s.OrgID != "" {
				fmt.Printf("  Org ID:    %s\n", s.OrgID)
			}
			if len(s.OUIDs) > 0 {
				fmt.Printf("  OU IDs:    %s\n", strings.Join(s.OUIDs, ", "))
			}

			return nil
		},
	}
}

func newScopeUpdateCmd() *cobra.Command {
	var (
		addAccounts  string
		addRegions   string
		setPartition string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update workspace scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			s := engine.Workspace.ScopeConfig

			if addAccounts != "" {
				for _, a := range strings.Split(addAccounts, ",") {
					a = strings.TrimSpace(a)
					if a != "" {
						s.AccountIDs = append(s.AccountIDs, a)
					}
				}
			}
			if addRegions != "" {
				for _, r := range strings.Split(addRegions, ",") {
					r = strings.TrimSpace(r)
					if r != "" {
						s.Regions = append(s.Regions, r)
					}
				}
			}
			if setPartition != "" {
				s.Partition = setPartition
			}

			// Deduplicate
			s.AccountIDs = dedupe(s.AccountIDs)
			s.Regions = dedupe(s.Regions)

			engine.Workspace.ScopeConfig = s
			engine.Workspace.UpdatedAt = time.Now().UTC()

			scopeJSON, _ := json.Marshal(s)
			_, err = engine.MetadataDB.Exec(
				"UPDATE workspaces SET scope_config = ?, updated_at = ? WHERE uuid = ?",
				string(scopeJSON),
				engine.Workspace.UpdatedAt.Format(time.RFC3339),
				engine.Workspace.UUID,
			)
			if err != nil {
				return fmt.Errorf("updating scope: %w", err)
			}

			fmt.Println("Scope updated.")
			if len(s.AccountIDs) > 0 {
				fmt.Printf("  Accounts: %s\n", strings.Join(s.AccountIDs, ", "))
			}
			if len(s.Regions) > 0 {
				fmt.Printf("  Regions:  %s\n", strings.Join(s.Regions, ", "))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&addAccounts, "add-accounts", "", "Comma-separated account IDs to add")
	cmd.Flags().StringVar(&addRegions, "add-regions", "", "Comma-separated regions to add")
	cmd.Flags().StringVar(&setPartition, "set-partition", "", "Set AWS partition")

	return cmd
}

func newScopeCheckCmd() *cobra.Command {
	var (
		region    string
		accountID string
	)

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check if a region or account is in scope",
		Long: `Validate whether a given region or account ID falls within the workspace scope.
Useful for pre-checking before operations.

Examples:
  stratus scope check --region us-east-1
  stratus scope check --account 123456789012
  stratus scope check --region eu-west-1 --account 123456789012`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if region == "" && accountID == "" {
				return fmt.Errorf("at least one of --region or --account is required")
			}

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			checker := scope.NewChecker(engine.Workspace.ScopeConfig)
			allOK := true

			if region != "" {
				if err := checker.CheckRegion(region); err != nil {
					fmt.Printf("Region %s: OUT OF SCOPE (%s)\n", region, err)
					allOK = false
				} else {
					fmt.Printf("Region %s: in scope\n", region)
				}
			}

			if accountID != "" {
				if err := checker.CheckAccount(accountID); err != nil {
					fmt.Printf("Account %s: OUT OF SCOPE (%s)\n", accountID, err)
					allOK = false
				} else {
					fmt.Printf("Account %s: in scope\n", accountID)
				}
			}

			if !allOK {
				return fmt.Errorf("scope check failed")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&region, "region", "", "AWS region to check")
	cmd.Flags().StringVar(&accountID, "account", "", "AWS account ID to check")

	return cmd
}

func dedupe(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
