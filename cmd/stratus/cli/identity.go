package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/identity"
	"golang.org/x/term"
)

// RegisterIdentityCommands adds identity management commands.
func RegisterIdentityCommands(root *cobra.Command) {
	idCmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id"},
		Short:   "Manage AWS identities (credential sources)",
	}

	idCmd.AddCommand(newIdentityAddCmd())
	idCmd.AddCommand(newIdentityListCmd())
	idCmd.AddCommand(newIdentityInfoCmd())
	idCmd.AddCommand(newIdentityArchiveCmd())

	root.AddCommand(idCmd)
}

func newIdentityAddCmd() *cobra.Command {
	addCmd := &cobra.Command{
		Use:   "add <type>",
		Short: "Import a new identity",
		Long: `Import a new AWS identity credential source.

Supported types:
  iam-key        Long-lived IAM access key + secret key pair
  sts-session    Pre-existing STS triple (access key + secret + session token)
  assume-role    Role ARN for AssumeRole
  web-identity   OIDC/JWT token for AssumeRoleWithWebIdentity
  cred-process   Shell command emitting credential_process JSON
  imds-capture   Operator-provided JSON snapshot of IMDS endpoint`,
	}

	addCmd.AddCommand(newIdentityAddIAMKeyCmd())
	addCmd.AddCommand(newIdentityAddSTSSessionCmd())
	addCmd.AddCommand(newIdentityAddAssumeRoleCmd())
	addCmd.AddCommand(newIdentityAddWebIdentityCmd())
	addCmd.AddCommand(newIdentityAddCredProcessCmd())
	addCmd.AddCommand(newIdentityAddIMDSCaptureCmd())

	return addCmd
}

func newIdentityAddIAMKeyCmd() *cobra.Command {
	var (
		accessKey string
		secretKey string
		label     string
		region    string
		tags      string
	)

	cmd := &cobra.Command{
		Use:   "iam-key",
		Short: "Import a long-lived IAM access key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			if accessKey == "" {
				return fmt.Errorf("--access-key is required")
			}

			// Prompt for secret key securely if not provided
			if secretKey == "" {
				fmt.Fprint(os.Stderr, "Enter secret access key: ")
				sk, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("reading secret key: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				secretKey = string(sk)
			}

			if label == "" {
				label = "iam-key-" + accessKey[len(accessKey)-4:]
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			var tagList []string
			if tags != "" {
				tagList = strings.Split(tags, ",")
			}

			id, session, err := broker.ImportIAMKey(identity.IAMKeyInput{
				AccessKey: accessKey,
				SecretKey: secretKey,
				Label:     label,
				Region:    region,
				Tags:      tagList,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Identity imported successfully.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Label:         %s\n", id.Label)
			fmt.Printf("  Session UUID:  %s\n", session.UUID)
			fmt.Printf("  Access Key:    %s...%s\n", accessKey[:4], accessKey[len(accessKey)-4:])
			fmt.Println("\nUse 'stratus sessions use " + session.UUID[:8] + "' to activate this session.")

			return nil
		},
	}

	cmd.Flags().StringVar(&accessKey, "access-key", "", "AWS access key ID (required)")
	cmd.Flags().StringVar(&secretKey, "secret-key", "", "AWS secret access key (will prompt if not provided)")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "Default AWS region")
	cmd.Flags().StringVar(&tags, "tags", "", "Comma-separated tags")

	return cmd
}

func newIdentityAddSTSSessionCmd() *cobra.Command {
	var (
		accessKey    string
		secretKey    string
		sessionToken string
		expiry       string
		label        string
		region       string
	)

	cmd := &cobra.Command{
		Use:   "sts-session",
		Short: "Import a pre-captured STS session triple",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			if accessKey == "" || sessionToken == "" {
				return fmt.Errorf("--access-key and --session-token are required")
			}

			if secretKey == "" {
				fmt.Fprint(os.Stderr, "Enter secret access key: ")
				sk, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("reading secret key: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				secretKey = string(sk)
			}

			if label == "" {
				label = "sts-session-" + accessKey[len(accessKey)-4:]
			}

			var expiryTime *time.Time
			if expiry != "" {
				t, err := time.Parse(time.RFC3339, expiry)
				if err != nil {
					return fmt.Errorf("invalid expiry format (expected RFC3339): %w", err)
				}
				expiryTime = &t
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, session, err := broker.ImportSTSSession(identity.STSSessionInput{
				AccessKey:    accessKey,
				SecretKey:    secretKey,
				SessionToken: sessionToken,
				Expiry:       expiryTime,
				Label:        label,
				Region:       region,
			})
			if err != nil {
				return err
			}

			fmt.Printf("STS session imported successfully.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Session UUID:  %s\n", session.UUID)
			if expiryTime != nil {
				fmt.Printf("  Expires:       %s\n", expiryTime.Format(time.RFC3339))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&accessKey, "access-key", "", "AWS access key ID")
	cmd.Flags().StringVar(&secretKey, "secret-key", "", "AWS secret access key")
	cmd.Flags().StringVar(&sessionToken, "session-token", "", "AWS session token")
	cmd.Flags().StringVar(&expiry, "expiry", "", "Session expiry (RFC3339 format)")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "Default AWS region")

	return cmd
}

func newIdentityAddAssumeRoleCmd() *cobra.Command {
	var (
		roleARN        string
		externalID     string
		sourceSession  string
		label          string
	)

	cmd := &cobra.Command{
		Use:   "assume-role",
		Short: "Import a role assumption identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			if roleARN == "" {
				return fmt.Errorf("--role-arn is required")
			}

			if label == "" {
				// Extract role name from ARN
				parts := strings.Split(roleARN, "/")
				label = "role-" + parts[len(parts)-1]
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, err := broker.ImportAssumeRole(identity.AssumeRoleInput{
				RoleARN:         roleARN,
				ExternalID:      externalID,
				SourceSessionID: sourceSession,
				Label:           label,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Assume-role identity imported.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Role ARN:      %s\n", roleARN)
			fmt.Printf("  Label:         %s\n", label)

			return nil
		},
	}

	cmd.Flags().StringVar(&roleARN, "role-arn", "", "Target role ARN (required)")
	cmd.Flags().StringVar(&externalID, "external-id", "", "STS external ID")
	cmd.Flags().StringVar(&sourceSession, "source-session", "", "Source session UUID for role chaining")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")

	return cmd
}

func newIdentityAddWebIdentityCmd() *cobra.Command {
	var (
		roleARN   string
		tokenFile string
		label     string
	)

	cmd := &cobra.Command{
		Use:   "web-identity",
		Short: "Import an OIDC/JWT web identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			if roleARN == "" {
				return fmt.Errorf("--role-arn is required")
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, err := broker.ImportWebIdentity(identity.WebIdentityInput{
				RoleARN:   roleARN,
				TokenFile: tokenFile,
				Label:     label,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Web identity imported.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Role ARN:      %s\n", roleARN)

			return nil
		},
	}

	cmd.Flags().StringVar(&roleARN, "role-arn", "", "Target role ARN")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "Path to OIDC/JWT token file")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")

	return cmd
}

func newIdentityAddCredProcessCmd() *cobra.Command {
	var (
		command string
		label   string
	)

	cmd := &cobra.Command{
		Use:   "cred-process",
		Short: "Import a credential_process identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			if command == "" {
				return fmt.Errorf("--command is required")
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, err := broker.ImportCredProcess(identity.CredProcessInput{
				Command: command,
				Label:   label,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Credential process identity imported.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Command:       %s\n", command)

			return nil
		},
	}

	cmd.Flags().StringVar(&command, "command", "", "Shell command for credential_process")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")

	return cmd
}

func newIdentityAddIMDSCaptureCmd() *cobra.Command {
	var (
		accessKey    string
		secretKey    string
		sessionToken string
		expiry       string
		roleName     string
		label        string
		region       string
		jsonFile     string
	)

	cmd := &cobra.Command{
		Use:   "imds-capture",
		Short: "Import credentials captured from EC2 Instance Metadata Service",
		Long: `Import AWS credentials obtained from an EC2 instance's metadata service (IMDS).

You can provide credentials either as individual flags or as a JSON file (--json-file)
containing the IMDS response from http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>.

JSON file format:
  {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2024-01-01T00:00:00Z"
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			// If JSON file provided, parse it
			if jsonFile != "" {
				data, err := os.ReadFile(jsonFile)
				if err != nil {
					return fmt.Errorf("reading JSON file: %w", err)
				}

				var imdsResp struct {
					AccessKeyID     string `json:"AccessKeyId"`
					SecretAccessKey string `json:"SecretAccessKey"`
					Token           string `json:"Token"`
					Expiration      string `json:"Expiration"`
					Code            string `json:"Code"`
					Type            string `json:"Type"`
				}
				if err := json.Unmarshal(data, &imdsResp); err != nil {
					return fmt.Errorf("parsing IMDS JSON: %w", err)
				}

				accessKey = imdsResp.AccessKeyID
				secretKey = imdsResp.SecretAccessKey
				sessionToken = imdsResp.Token
				if imdsResp.Expiration != "" {
					expiry = imdsResp.Expiration
				}
			}

			if accessKey == "" || secretKey == "" || sessionToken == "" {
				return fmt.Errorf("--access-key, --secret-key, and --session-token are required (or use --json-file)")
			}

			var expiryTime *time.Time
			if expiry != "" {
				t, err := time.Parse(time.RFC3339, expiry)
				if err != nil {
					return fmt.Errorf("invalid expiry format (expected RFC3339): %w", err)
				}
				expiryTime = &t
			}

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, session, err := broker.ImportIMDSCapture(identity.IMDSCaptureInput{
				AccessKey:    accessKey,
				SecretKey:    secretKey,
				SessionToken: sessionToken,
				Expiry:       expiryTime,
				RoleName:     roleName,
				Label:        label,
				Region:       region,
			})
			if err != nil {
				return err
			}

			fmt.Printf("IMDS capture imported successfully.\n")
			fmt.Printf("  Identity UUID: %s\n", id.UUID)
			fmt.Printf("  Label:         %s\n", id.Label)
			fmt.Printf("  Session UUID:  %s\n", session.UUID)
			if expiryTime != nil {
				fmt.Printf("  Expires:       %s\n", expiryTime.Format(time.RFC3339))
			}
			fmt.Println("\nUse 'stratus sessions use " + session.UUID[:8] + "' to activate this session.")

			return nil
		},
	}

	cmd.Flags().StringVar(&jsonFile, "json-file", "", "Path to IMDS JSON response file")
	cmd.Flags().StringVar(&accessKey, "access-key", "", "AWS access key ID")
	cmd.Flags().StringVar(&secretKey, "secret-key", "", "AWS secret access key")
	cmd.Flags().StringVar(&sessionToken, "session-token", "", "AWS session token")
	cmd.Flags().StringVar(&expiry, "expiry", "", "Credential expiry (RFC3339 format)")
	cmd.Flags().StringVar(&roleName, "role-name", "", "EC2 instance role name")
	cmd.Flags().StringVar(&label, "label", "", "Human-readable label")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "Default AWS region")

	return cmd
}

func newIdentityListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all identities in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			identities, err := broker.ListIdentities()
			if err != nil {
				return err
			}

			if len(identities) == 0 {
				fmt.Println("No identities found. Import one with: stratus identity add <type>")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tLABEL\tTYPE\tPRINCIPAL\tACCOUNT\tACQUIRED")
			for _, id := range identities {
				principal := id.PrincipalARN
				if principal == "" {
					principal = "(unverified)"
				}
				account := id.AccountID
				if account == "" {
					account = "(unknown)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					id.UUID[:8],
					id.Label,
					id.SourceType,
					truncate(string(principal), 40),
					account,
					id.AcquiredAt.Format("2006-01-02 15:04"),
				)
			}
			w.Flush()

			return nil
		},
	}
}

func newIdentityInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <uuid|label>",
		Short: "Show identity details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			id, err := broker.GetIdentity(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Identity: %s\n", id.Label)
			fmt.Printf("  UUID:           %s\n", id.UUID)
			fmt.Printf("  Source Type:    %s\n", id.SourceType)
			fmt.Printf("  Principal ARN:  %s\n", id.PrincipalARN)
			fmt.Printf("  Principal Type: %s\n", id.PrincipalType)
			fmt.Printf("  Account ID:     %s\n", id.AccountID)
			fmt.Printf("  Acquired:       %s\n", id.AcquiredAt.Format(time.RFC3339))
			if id.RiskNotes != "" {
				fmt.Printf("  Risk Notes:     %s\n", id.RiskNotes)
			}
			if len(id.Tags) > 0 {
				fmt.Printf("  Tags:           %s\n", strings.Join(id.Tags, ", "))
			}

			return nil
		},
	}
}

func newIdentityArchiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "archive <uuid|label>",
		Short: "Archive an identity (soft delete)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			broker := identity.NewBroker(engine.MetadataDB, engine.Vault, engine.AuditLogger, engine.Workspace.UUID)

			if err := broker.ArchiveIdentity(args[0]); err != nil {
				return err
			}

			fmt.Printf("Identity archived: %s\n", args[0])
			return nil
		},
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
