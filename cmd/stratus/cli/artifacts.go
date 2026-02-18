package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// RegisterArtifactCommands adds artifact management commands.
func RegisterArtifactCommands(root *cobra.Command) {
	artCmd := &cobra.Command{
		Use:     "artifacts",
		Aliases: []string{"art"},
		Short:   "Manage workspace artifacts",
	}

	artCmd.AddCommand(newArtifactListCmd())
	artCmd.AddCommand(newArtifactShowCmd())

	root.AddCommand(artCmd)
}

func newArtifactListCmd() *cobra.Command {
	var (
		runUUID     string
		sessionUUID string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List artifacts in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			query := "SELECT uuid, label, artifact_type, byte_size, created_at, session_uuid FROM artifacts WHERE workspace_uuid = ?"
			qargs := []any{engine.Workspace.UUID}

			if runUUID != "" {
				query += " AND run_uuid = ?"
				qargs = append(qargs, runUUID)
			}
			if sessionUUID != "" {
				query += " AND session_uuid = ?"
				qargs = append(qargs, sessionUUID)
			}
			query += " ORDER BY created_at DESC"

			rows, err := engine.MetadataDB.Query(query, qargs...)
			if err != nil {
				return err
			}
			defer rows.Close()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tLABEL\tTYPE\tSIZE\tCREATED")

			count := 0
			for rows.Next() {
				var uuid, label, artType, createdAt, sessUUID string
				var size int64
				rows.Scan(&uuid, &label, &artType, &size, &createdAt, &sessUUID)
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", uuid[:8], label, artType, size, createdAt)
				count++
			}
			w.Flush()

			if count == 0 {
				fmt.Println("No artifacts found.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&runUUID, "run", "", "Filter by run UUID")
	cmd.Flags().StringVar(&sessionUUID, "session", "", "Filter by session UUID")

	return cmd
}

func newArtifactShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <uuid>",
		Short: "Show artifact details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			var uuid, label, artType, contentHash, storagePath, createdAt, createdBy string
			var size int64
			var isSensitive int

			err = engine.MetadataDB.QueryRow(
				`SELECT uuid, label, artifact_type, content_hash, storage_path, byte_size, created_at, created_by, is_sensitive
				 FROM artifacts WHERE uuid = ? OR uuid LIKE ?`,
				args[0], args[0]+"%",
			).Scan(&uuid, &label, &artType, &contentHash, &storagePath, &size, &createdAt, &createdBy, &isSensitive)
			if err != nil {
				return fmt.Errorf("artifact not found: %s", args[0])
			}

			fmt.Printf("Artifact: %s\n", label)
			fmt.Printf("  UUID:         %s\n", uuid)
			fmt.Printf("  Type:         %s\n", artType)
			fmt.Printf("  Content Hash: %s\n", contentHash)
			fmt.Printf("  Storage Path: %s\n", storagePath)
			fmt.Printf("  Size:         %d bytes\n", size)
			fmt.Printf("  Created:      %s\n", createdAt)
			fmt.Printf("  Created By:   %s\n", createdBy)
			if isSensitive != 0 {
				fmt.Printf("  Sensitive:    yes (encrypted at rest)\n")
			}

			return nil
		},
	}
}
