package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// RegisterNoteCommands adds note management commands.
func RegisterNoteCommands(root *cobra.Command) {
	noteCmd := &cobra.Command{
		Use:   "note",
		Short: "Manage engagement notes",
	}

	noteCmd.AddCommand(newNoteAddCmd())
	noteCmd.AddCommand(newNoteListCmd())
	noteCmd.AddCommand(newNoteShowCmd())
	noteCmd.AddCommand(newNoteUpdateCmd())
	noteCmd.AddCommand(newNoteDeleteCmd())

	root.AddCommand(noteCmd)
}

func newNoteAddCmd() *cobra.Command {
	var (
		sessionID string
		runID     string
		nodeID    string
	)

	cmd := &cobra.Command{
		Use:   "add [text]",
		Short: "Add a note to the workspace",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			content := strings.Join(args, " ")
			noteUUID := uuid.New().String()
			now := time.Now().UTC()

			_, err = engine.MetadataDB.Exec(
				`INSERT INTO notes (uuid, workspace_uuid, session_uuid, run_uuid, node_id, content, created_at, updated_at, created_by)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				noteUUID, engine.Workspace.UUID,
				sessionID, runID, nodeID,
				content,
				now.Format(time.RFC3339), now.Format(time.RFC3339),
				"local",
			)
			if err != nil {
				return fmt.Errorf("saving note: %w", err)
			}

			fmt.Printf("Note added: %s\n", noteUUID[:8])
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Associate with session UUID")
	cmd.Flags().StringVar(&runID, "run", "", "Associate with run UUID")
	cmd.Flags().StringVar(&nodeID, "node", "", "Associate with graph node ARN")

	return cmd
}

func newNoteListCmd() *cobra.Command {
	var (
		sessionFilter string
		runFilter     string
		nodeFilter    string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all notes in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			query := "SELECT uuid, content, session_uuid, run_uuid, node_id, created_at, created_by FROM notes WHERE workspace_uuid = ?"
			qargs := []any{engine.Workspace.UUID}

			if sessionFilter != "" {
				query += " AND session_uuid = ?"
				qargs = append(qargs, sessionFilter)
			}
			if runFilter != "" {
				query += " AND run_uuid = ?"
				qargs = append(qargs, runFilter)
			}
			if nodeFilter != "" {
				query += " AND node_id = ?"
				qargs = append(qargs, nodeFilter)
			}
			query += " ORDER BY created_at DESC"

			rows, err := engine.MetadataDB.Query(query, qargs...)
			if err != nil {
				return err
			}
			defer rows.Close()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tCONTENT\tCREATED\tBY")

			count := 0
			for rows.Next() {
				var id, content, sessUUID, runUUID, nodeID, createdAt, createdBy string
				rows.Scan(&id, &content, &sessUUID, &runUUID, &nodeID, &createdAt, &createdBy)
				if len(content) > 60 {
					content = content[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id[:8], content, createdAt, createdBy)
				count++
			}
			w.Flush()

			if count == 0 {
				fmt.Println("No notes found.")
			} else {
				fmt.Printf("\n%d note(s) found.\n", count)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&sessionFilter, "session", "", "Filter by session UUID")
	cmd.Flags().StringVar(&runFilter, "run", "", "Filter by run UUID")
	cmd.Flags().StringVar(&nodeFilter, "node", "", "Filter by graph node ARN")

	return cmd
}

func newNoteShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <uuid>",
		Short: "Show full note content",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			var noteUUID, content, sessUUID, runUUID, nodeID, createdAt, updatedAt, createdBy string
			err = engine.MetadataDB.QueryRow(
				`SELECT uuid, content, session_uuid, run_uuid, node_id, created_at, updated_at, created_by
				 FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?`,
				args[0], args[0]+"%", engine.Workspace.UUID,
			).Scan(&noteUUID, &content, &sessUUID, &runUUID, &nodeID, &createdAt, &updatedAt, &createdBy)
			if err != nil {
				return fmt.Errorf("note not found: %s", args[0])
			}

			fmt.Printf("Note: %s\n", noteUUID)
			fmt.Printf("  Created:  %s by %s\n", createdAt, createdBy)
			if createdAt != updatedAt {
				fmt.Printf("  Updated:  %s\n", updatedAt)
			}
			if sessUUID != "" {
				fmt.Printf("  Session:  %s\n", sessUUID)
			}
			if runUUID != "" {
				fmt.Printf("  Run:      %s\n", runUUID)
			}
			if nodeID != "" {
				fmt.Printf("  Node:     %s\n", nodeID)
			}
			fmt.Printf("\n%s\n", content)

			return nil
		},
	}
}

func newNoteUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update <uuid> [new text]",
		Short: "Update a note's content",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			noteID := args[0]
			newContent := strings.Join(args[1:], " ")
			now := time.Now().UTC()

			// Resolve prefix match
			var fullUUID string
			err = engine.MetadataDB.QueryRow(
				"SELECT uuid FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?",
				noteID, noteID+"%", engine.Workspace.UUID,
			).Scan(&fullUUID)
			if err != nil {
				return fmt.Errorf("note not found: %s", noteID)
			}

			_, err = engine.MetadataDB.Exec(
				"UPDATE notes SET content = ?, updated_at = ? WHERE uuid = ?",
				newContent, now.Format(time.RFC3339), fullUUID,
			)
			if err != nil {
				return fmt.Errorf("updating note: %w", err)
			}

			fmt.Printf("Note updated: %s\n", fullUUID[:8])
			return nil
		},
	}
}

func newNoteDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <uuid>",
		Short: "Delete a note",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			noteID := args[0]

			// Resolve prefix match
			var fullUUID string
			err = engine.MetadataDB.QueryRow(
				"SELECT uuid FROM notes WHERE (uuid = ? OR uuid LIKE ?) AND workspace_uuid = ?",
				noteID, noteID+"%", engine.Workspace.UUID,
			).Scan(&fullUUID)
			if err != nil {
				return fmt.Errorf("note not found: %s", noteID)
			}

			_, err = engine.MetadataDB.Exec(
				"DELETE FROM notes WHERE uuid = ?",
				fullUUID,
			)
			if err != nil {
				return fmt.Errorf("deleting note: %w", err)
			}

			fmt.Printf("Note deleted: %s\n", fullUUID[:8])
			return nil
		},
	}
}
