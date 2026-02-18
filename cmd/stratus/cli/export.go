package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// RegisterExportCommands adds evidence export commands.
func RegisterExportCommands(root *cobra.Command) {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export workspace evidence bundle",
	}

	var (
		format string
		output string
	)

	exportCmd.Flags().StringVar(&format, "format", "json", "Export format (json, markdown)")
	exportCmd.Flags().StringVar(&output, "output", "", "Output directory (required)")

	exportCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if output == "" {
			return fmt.Errorf("--output is required")
		}

		engine, err := loadActiveEngine()
		if err != nil {
			return err
		}
		defer engine.Close()

		// Create export directory structure
		dirs := []string{
			output,
			filepath.Join(output, "identities"),
			filepath.Join(output, "sessions"),
			filepath.Join(output, "graph"),
			filepath.Join(output, "runs"),
			filepath.Join(output, "artifacts"),
			filepath.Join(output, "notes"),
		}
		for _, d := range dirs {
			if err := os.MkdirAll(d, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", d, err)
			}
		}

		// Export workspace metadata (no secrets)
		wsData, _ := json.MarshalIndent(map[string]any{
			"uuid":        engine.Workspace.UUID,
			"name":        engine.Workspace.Name,
			"description": engine.Workspace.Description,
			"owner":       engine.Workspace.Owner,
			"created_at":  engine.Workspace.CreatedAt,
			"scope":       engine.Workspace.ScopeConfig,
			"exported_at": time.Now().UTC(),
		}, "", "  ")
		os.WriteFile(filepath.Join(output, "workspace.json"), wsData, 0644)

		// Export identities (no secret material)
		identityRows, err := engine.MetadataDB.Query(
			"SELECT uuid, label, account_id, principal_arn, principal_type, source_type, acquired_at, tags FROM identities WHERE workspace_uuid = ?",
			engine.Workspace.UUID,
		)
		if err == nil {
			defer identityRows.Close()
			idCount := 0
			for identityRows.Next() {
				var uuid, label, accountID, principalARN, principalType, sourceType, acquiredAt, tags string
				identityRows.Scan(&uuid, &label, &accountID, &principalARN, &principalType, &sourceType, &acquiredAt, &tags)
				data, _ := json.MarshalIndent(map[string]string{
					"uuid":           uuid,
					"label":          label,
					"account_id":     accountID,
					"principal_arn":  principalARN,
					"principal_type": principalType,
					"source_type":    sourceType,
					"acquired_at":    acquiredAt,
				}, "", "  ")
				os.WriteFile(filepath.Join(output, "identities", uuid+".json"), data, 0644)
				idCount++
			}
			fmt.Printf("  Exported %d identities\n", idCount)
		}

		// Export sessions (no secret material)
		sessionRows, err := engine.MetadataDB.Query(
			"SELECT uuid, session_name, region, health_status, created_at FROM sessions WHERE workspace_uuid = ?",
			engine.Workspace.UUID,
		)
		if err == nil {
			defer sessionRows.Close()
			sessCount := 0
			for sessionRows.Next() {
				var uuid, name, region, health, createdAt string
				sessionRows.Scan(&uuid, &name, &region, &health, &createdAt)
				data, _ := json.MarshalIndent(map[string]string{
					"uuid":          uuid,
					"session_name":  name,
					"region":        region,
					"health_status": health,
					"created_at":    createdAt,
				}, "", "  ")
				os.WriteFile(filepath.Join(output, "sessions", uuid+".json"), data, 0644)
				sessCount++
			}
			fmt.Printf("  Exported %d sessions\n", sessCount)
		}

		fmt.Printf("Evidence bundle exported to: %s\n", output)
		return nil
	}

	root.AddCommand(exportCmd)
}
