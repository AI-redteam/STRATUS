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
	return &cobra.Command{
		Use:   "list",
		Short: "List all notes in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			rows, err := engine.MetadataDB.Query(
				"SELECT uuid, content, created_at, created_by FROM notes WHERE workspace_uuid = ? ORDER BY created_at DESC",
				engine.Workspace.UUID,
			)
			if err != nil {
				return err
			}
			defer rows.Close()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tCONTENT\tCREATED\tBY")

			count := 0
			for rows.Next() {
				var id, content, createdAt, createdBy string
				rows.Scan(&id, &content, &createdAt, &createdBy)
				if len(content) > 60 {
					content = content[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id[:8], content, createdAt, createdBy)
				count++
			}
			w.Flush()

			if count == 0 {
				fmt.Println("No notes found.")
			}

			return nil
		},
	}
}
