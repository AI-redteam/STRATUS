package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/session"
)

// RegisterSessionCommands adds session management commands.
func RegisterSessionCommands(root *cobra.Command) {
	sessCmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage AWS sessions (active STS contexts)",
	}

	sessCmd.AddCommand(newSessionListCmd())
	sessCmd.AddCommand(newSessionUseCmd())
	sessCmd.AddCommand(newSessionPushCmd())
	sessCmd.AddCommand(newSessionPopCmd())
	sessCmd.AddCommand(newSessionPeekCmd())
	sessCmd.AddCommand(newSessionWhoamiCmd())
	sessCmd.AddCommand(newSessionHealthCmd())
	sessCmd.AddCommand(newSessionExpireCmd())

	root.AddCommand(sessCmd)
}

func newSessionListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all sessions in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			sessions, err := mgr.ListSessions()
			if err != nil {
				return err
			}

			if len(sessions) == 0 {
				fmt.Println("No sessions found. Import an identity first.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tNAME\tREGION\tKEY_ID\tHEALTH\tEXPIRY\tACTIVE")
			for _, s := range sessions {
				expiry := "(none)"
				if s.Expiry != nil {
					remaining := time.Until(*s.Expiry)
					if remaining <= 0 {
						expiry = "EXPIRED"
					} else {
						expiry = fmt.Sprintf("%dm", int(remaining.Minutes()))
					}
				}

				active := ""
				if s.IsActive {
					active = "*"
				}

				keyID := s.AWSAccessKeyID
				if len(keyID) > 8 {
					keyID = keyID[:4] + "..." + keyID[len(keyID)-4:]
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.UUID[:8],
					s.SessionName,
					s.Region,
					keyID,
					s.HealthStatus,
					expiry,
					active,
				)
			}
			w.Flush()

			return nil
		},
	}
}

func newSessionUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <uuid|label>",
		Short: "Activate a session (push to context stack)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			s, err := mgr.Use(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Session activated: %s (%s)\n", s.SessionName, s.UUID[:8])
			fmt.Printf("  Region: %s\n", s.Region)
			if s.Expiry != nil {
				fmt.Printf("  Expiry: %s (%dm remaining)\n",
					s.Expiry.Format(time.RFC3339),
					int(time.Until(*s.Expiry).Minutes()),
				)
			}
			return nil
		},
	}
}

func newSessionPushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push <uuid|label>",
		Short: "Push a session onto the context stack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			s, err := mgr.Push(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Session pushed: %s (%s)\n", s.SessionName, s.UUID[:8])
			return nil
		},
	}
}

func newSessionPopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pop",
		Short: "Pop the current session from the context stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			prev, err := mgr.Pop()
			if err != nil {
				return err
			}

			if prev != nil {
				fmt.Printf("Reverted to session: %s (%s)\n", prev.SessionName, prev.UUID[:8])
			} else {
				fmt.Println("Context stack is now empty. No active session.")
			}
			return nil
		},
	}
}

func newSessionPeekCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "peek",
		Short: "Show the context stack without modifying it",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			stack, err := mgr.Peek()
			if err != nil {
				return err
			}

			if len(stack) == 0 {
				fmt.Println("Context stack is empty.")
				return nil
			}

			fmt.Println("Context stack (top → bottom):")
			for i, s := range stack {
				marker := "  "
				if i == 0 {
					marker = "→ "
				}
				expiry := ""
				if s.Expiry != nil {
					remaining := time.Until(*s.Expiry)
					if remaining <= 0 {
						expiry = " [EXPIRED]"
					} else {
						expiry = fmt.Sprintf(" [%dm]", int(remaining.Minutes()))
					}
				}
				fmt.Printf("%s%s (%s) [%s] %s%s\n",
					marker, s.SessionName, s.UUID[:8], s.Region, s.HealthStatus, expiry)
			}
			return nil
		},
	}
}

func newSessionWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current session's caller identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			s, err := mgr.GetActiveSession()
			if err != nil {
				return err
			}

			fmt.Printf("Session:      %s (%s)\n", s.SessionName, s.UUID[:8])
			fmt.Printf("Access Key:   %s\n", s.AWSAccessKeyID)
			fmt.Printf("Region:       %s\n", s.Region)
			fmt.Printf("Health:       %s\n", s.HealthStatus)
			if s.Expiry != nil {
				remaining := time.Until(*s.Expiry)
				fmt.Printf("Expiry:       %s (%dm remaining)\n",
					s.Expiry.Format(time.RFC3339), int(remaining.Minutes()))
			} else {
				fmt.Printf("Expiry:       (none — long-lived key)\n")
			}
			if s.ChainParentSessionUUID != nil {
				fmt.Printf("Chain Parent: %s\n", *s.ChainParentSessionUUID)
			}
			if s.LastVerifiedAt != nil {
				fmt.Printf("Verified:     %s\n", s.LastVerifiedAt.Format(time.RFC3339))
			}

			return nil
		},
	}
}

func newSessionHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check health status of all sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			sessions, err := mgr.ListSessions()
			if err != nil {
				return err
			}

			if len(sessions) == 0 {
				fmt.Println("No sessions to check.")
				return nil
			}

			// Check for expiring sessions
			expiring, _ := mgr.CheckExpiry()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tNAME\tHEALTH\tEXPIRY\tVERIFIED")
			for _, s := range sessions {
				expiry := "(none)"
				if s.Expiry != nil {
					remaining := time.Until(*s.Expiry)
					if remaining <= 0 {
						expiry = "EXPIRED"
					} else {
						expiry = fmt.Sprintf("%dm", int(remaining.Minutes()))
					}
				}

				verified := "(never)"
				if s.LastVerifiedAt != nil {
					verified = s.LastVerifiedAt.Format("15:04:05")
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					s.UUID[:8], s.SessionName, s.HealthStatus, expiry, verified)
			}
			w.Flush()

			if len(expiring) > 0 {
				fmt.Printf("\nWarning: %d session(s) expiring soon or already expired.\n", len(expiring))
			}

			return nil
		},
	}
}

func newSessionExpireCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "expire <uuid>",
		Short: "Manually expire a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			mgr := session.NewManager(engine.MetadataDB, engine.AuditLogger, engine.Workspace.UUID)
			if err := mgr.ExpireSession(args[0]); err != nil {
				return err
			}

			fmt.Printf("Session expired: %s\n", args[0])
			return nil
		},
	}
}
