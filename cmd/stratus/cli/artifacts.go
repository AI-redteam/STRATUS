package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/artifact"
	"github.com/stratus-framework/stratus/internal/core"
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
	artCmd.AddCommand(newArtifactCreateCmd())
	artCmd.AddCommand(newArtifactGetCmd())
	artCmd.AddCommand(newArtifactVerifyCmd())

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

			store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)
			arts, err := store.List(runUUID, sessionUUID)
			if err != nil {
				return err
			}

			if len(arts) == 0 {
				fmt.Println("No artifacts found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tLABEL\tTYPE\tSIZE\tCREATED")
			for _, a := range arts {
				uuid := a.UUID
				if len(uuid) > 8 {
					uuid = uuid[:8] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
					uuid, a.Label, a.ArtifactType, a.ByteSize,
					a.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			w.Flush()

			fmt.Printf("\n%d artifact(s) found.\n", len(arts))
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
		Short: "Show artifact metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)
			art, err := store.Get(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Artifact: %s\n", art.Label)
			fmt.Printf("  UUID:         %s\n", art.UUID)
			fmt.Printf("  Type:         %s\n", art.ArtifactType)
			fmt.Printf("  Content Hash: %s\n", art.ContentHash)
			fmt.Printf("  Storage Path: %s\n", art.StoragePath)
			fmt.Printf("  Size:         %d bytes\n", art.ByteSize)
			fmt.Printf("  Created:      %s\n", art.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Created By:   %s\n", art.CreatedBy)
			if art.RunUUID != nil {
				fmt.Printf("  Run UUID:     %s\n", *art.RunUUID)
			}
			fmt.Printf("  Session UUID: %s\n", art.SessionUUID)
			if len(art.Tags) > 0 {
				fmt.Printf("  Tags:         %s\n", strings.Join(art.Tags, ", "))
			}
			if art.IsSensitive {
				fmt.Printf("  Sensitive:    yes\n")
			}

			return nil
		},
	}
}

func newArtifactCreateCmd() *cobra.Command {
	var (
		label       string
		artType     string
		sessionUUID string
		tags        string
		sensitive   bool
	)

	cmd := &cobra.Command{
		Use:   "create <file-path>",
		Short: "Upload a file as an artifact",
		Long: `Upload a local file to the workspace artifact store.
The file contents are hashed with SHA-256 and stored content-addressed.

Examples:
  stratus artifacts create evidence.json --label "API response" --type json_result
  stratus artifacts create screenshot.png --label "Console access" --type api_proof --sensitive`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			if label == "" {
				label = filepath.Base(filePath)
			}

			at := core.ArtifactType(artType)

			var tagList []string
			if tags != "" {
				tagList = strings.Split(tags, ",")
				for i := range tagList {
					tagList[i] = strings.TrimSpace(tagList[i])
				}
			}

			store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)

			// If session UUID not given, try to resolve active session
			if sessionUUID == "" {
				var sessUUID string
				err := engine.MetadataDB.QueryRow(
					"SELECT uuid FROM sessions WHERE workspace_uuid = ? AND is_active = 1 ORDER BY activated_at DESC LIMIT 1",
					engine.Workspace.UUID,
				).Scan(&sessUUID)
				if err == nil {
					sessionUUID = sessUUID
				}
			}

			art, err := store.Create(artifact.CreateInput{
				SessionUUID:  sessionUUID,
				ArtifactType: at,
				Label:        label,
				Content:      content,
				CreatedBy:    "local",
				Tags:         tagList,
				IsSensitive:  sensitive,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Artifact created: %s\n", art.UUID)
			fmt.Printf("  Label:  %s\n", art.Label)
			fmt.Printf("  Hash:   %s\n", art.ContentHash)
			fmt.Printf("  Size:   %d bytes\n", art.ByteSize)

			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "Artifact label (default: filename)")
	cmd.Flags().StringVar(&artType, "type", "api_proof", "Artifact type (json_result, api_proof, note, graph_snapshot, export_bundle)")
	cmd.Flags().StringVar(&sessionUUID, "session", "", "Associated session UUID (default: active session)")
	cmd.Flags().StringVar(&tags, "tags", "", "Comma-separated tags")
	cmd.Flags().BoolVar(&sensitive, "sensitive", false, "Mark artifact as sensitive")

	return cmd
}

func newArtifactGetCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "get <uuid>",
		Short: "Retrieve artifact content",
		Long: `Retrieve the raw content of an artifact. By default prints to stdout.
Use --output to write to a file instead.

Examples:
  stratus artifacts get abc123
  stratus artifacts get abc123 --output evidence.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)
			art, err := store.Get(args[0])
			if err != nil {
				return err
			}

			data, err := store.ReadContent(art)
			if err != nil {
				return err
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0600); err != nil {
					return fmt.Errorf("writing output file: %w", err)
				}
				fmt.Printf("Written %d bytes to %s (hash: %s)\n", len(data), outputPath, art.ContentHash)
				return nil
			}

			os.Stdout.Write(data)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write content to file instead of stdout")

	return cmd
}

func newArtifactVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify integrity of all stored artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			store := artifact.NewStore(engine.MetadataDB, engine.Workspace.Path, engine.Workspace.UUID)
			valid, invalid, err := store.VerifyIntegrity()
			if err != nil {
				return err
			}

			fmt.Printf("Verified: %d artifact(s) OK\n", valid)
			if len(invalid) > 0 {
				fmt.Printf("Invalid:  %d artifact(s)\n", len(invalid))
				for _, msg := range invalid {
					fmt.Printf("  - %s\n", msg)
				}
				return fmt.Errorf("%d artifact(s) failed integrity check", len(invalid))
			}

			return nil
		},
	}
}
