// stratus-server is the teamserver binary for multi-operator STRATUS engagements.
// It exposes the STRATUS API via gRPC with JSON-RPC dispatch, supporting
// workspace, identity, session, graph, module, and audit operations.
// Supports mutual TLS (mTLS) for authenticated multi-operator collaboration.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/grpcapi"
	"github.com/stratus-framework/stratus/internal/pki"
)

var version = "0.1.0-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "stratus-server",
		Short:   "STRATUS Teamserver — multi-operator collaboration server",
		Version: version,
	}

	rootCmd.AddCommand(newServeCmd())
	rootCmd.AddCommand(newInitPKICmd())
	rootCmd.AddCommand(newGenClientCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the teamserver",
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			wsPath, _ := cmd.Flags().GetString("workspace")
			passphrase, _ := cmd.Flags().GetString("passphrase")
			pkiDir, _ := cmd.Flags().GetString("pki-dir")
			insecure, _ := cmd.Flags().GetBool("insecure")

			if wsPath == "" {
				return fmt.Errorf("--workspace is required")
			}
			if passphrase == "" {
				return fmt.Errorf("--passphrase is required (use env STRATUS_PASSPHRASE for automation)")
			}

			fmt.Printf("Opening workspace: %s\n", wsPath)

			engine, err := core.OpenWorkspace(wsPath, passphrase)
			if err != nil {
				return fmt.Errorf("opening workspace: %w", err)
			}
			defer engine.Close()

			fmt.Printf("Workspace loaded: %s (%s)\n", engine.Workspace.Name, engine.Workspace.UUID[:8])

			var server *grpcapi.Server

			if insecure {
				fmt.Printf("WARNING: Starting in insecure mode (no mTLS) on %s\n", addr)
				server, err = grpcapi.NewTCPServer(addr, engine)
			} else {
				if pkiDir == "" {
					pkiDir = filepath.Join(wsPath, "pki")
				}

				tlsCfg, tlsErr := loadPKI(pkiDir)
				if tlsErr != nil {
					return fmt.Errorf("loading PKI from %s: %w\nRun 'stratus-server init-pki' first, or use --insecure for dev mode", pkiDir, tlsErr)
				}

				fmt.Printf("mTLS enabled (PKI: %s)\n", pkiDir)
				server, err = grpcapi.NewMTLSServer(addr, engine, tlsCfg)
			}

			if err != nil {
				return fmt.Errorf("starting server: %w", err)
			}

			fmt.Printf("STRATUS Teamserver starting on %s\n", addr)

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigCh
				fmt.Println("\nShutting down...")
				server.Stop()
			}()

			fmt.Println("Teamserver ready. Waiting for connections...")
			return server.Serve()
		},
	}

	cmd.Flags().String("addr", ":50051", "Server listen address")
	cmd.Flags().String("workspace", "", "Path to workspace directory (required)")
	cmd.Flags().String("passphrase", os.Getenv("STRATUS_PASSPHRASE"), "Vault passphrase")
	cmd.Flags().String("pki-dir", "", "PKI directory (default: <workspace>/pki)")
	cmd.Flags().Bool("insecure", false, "Disable mTLS (dev/local only)")

	return cmd
}

func newInitPKICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-pki",
		Short: "Initialize PKI (generate CA and server certificates)",
		Long: `Generate a self-signed Certificate Authority and server certificate
for the teamserver. The CA is used to sign operator client certificates
for mutual TLS authentication.

The PKI directory will contain:
  ca.crt         — CA certificate (distribute to operators)
  ca.key         — CA private key (keep secure!)
  server.crt     — Server certificate
  server.key     — Server private key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pkiDir, _ := cmd.Flags().GetString("pki-dir")
			org, _ := cmd.Flags().GetString("org")
			hosts, _ := cmd.Flags().GetStringSlice("hosts")
			caValidityYears, _ := cmd.Flags().GetInt("ca-validity-years")
			serverValidityDays, _ := cmd.Flags().GetInt("server-validity-days")

			if pkiDir == "" {
				return fmt.Errorf("--pki-dir is required")
			}

			if err := os.MkdirAll(pkiDir, 0700); err != nil {
				return fmt.Errorf("creating PKI directory: %w", err)
			}

			// Check for existing CA
			if _, err := os.Stat(filepath.Join(pkiDir, "ca.crt")); err == nil {
				return fmt.Errorf("PKI already initialized in %s (ca.crt exists)", pkiDir)
			}

			fmt.Printf("Generating PKI in %s\n", pkiDir)

			// Generate CA
			caValidity := time.Duration(caValidityYears) * 365 * 24 * time.Hour
			ca, err := pki.GenerateCA(org, caValidity)
			if err != nil {
				return fmt.Errorf("generating CA: %w", err)
			}

			if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), ca.CertPEM, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(pkiDir, "ca.key"), ca.KeyPEM, 0600); err != nil {
				return err
			}
			fmt.Println("  CA certificate generated")

			// Generate server cert
			if len(hosts) == 0 {
				hosts = []string{"localhost", "127.0.0.1"}
			}
			serverValidity := time.Duration(serverValidityDays) * 24 * time.Hour
			serverBundle, err := pki.GenerateServerCert(ca, hosts, serverValidity)
			if err != nil {
				return fmt.Errorf("generating server certificate: %w", err)
			}

			if err := os.WriteFile(filepath.Join(pkiDir, "server.crt"), serverBundle.CertPEM, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(pkiDir, "server.key"), serverBundle.KeyPEM, 0600); err != nil {
				return err
			}
			fmt.Println("  Server certificate generated")

			fmt.Printf("\nPKI initialized. Distribute ca.crt to operators.\n")
			fmt.Printf("Generate client certs with: stratus-server gen-client --pki-dir %s --name <operator>\n", pkiDir)
			return nil
		},
	}

	cmd.Flags().String("pki-dir", "", "PKI output directory (required)")
	cmd.Flags().String("org", "STRATUS", "Organization name for certificates")
	cmd.Flags().StringSlice("hosts", nil, "Server hostnames/IPs for SAN (default: localhost,127.0.0.1)")
	cmd.Flags().Int("ca-validity-years", 5, "CA certificate validity in years")
	cmd.Flags().Int("server-validity-days", 365, "Server certificate validity in days")

	return cmd
}

func newGenClientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-client",
		Short: "Generate a client certificate for an operator",
		Long: `Generate a client certificate signed by the CA for operator authentication.
The operator name is embedded in the certificate's Common Name field.

Output files:
  <name>.crt     — Client certificate
  <name>.key     — Client private key
  ca.crt         — CA certificate (copy for operator)

The operator needs all three files to connect to the teamserver.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pkiDir, _ := cmd.Flags().GetString("pki-dir")
			name, _ := cmd.Flags().GetString("name")
			outputDir, _ := cmd.Flags().GetString("output")
			validityDays, _ := cmd.Flags().GetInt("validity-days")

			if pkiDir == "" {
				return fmt.Errorf("--pki-dir is required")
			}
			if name == "" {
				return fmt.Errorf("--name is required (operator name)")
			}

			// Load CA
			caCertPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
			if err != nil {
				return fmt.Errorf("reading CA cert: %w (run init-pki first)", err)
			}
			caKeyPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.key"))
			if err != nil {
				return fmt.Errorf("reading CA key: %w", err)
			}
			ca := &pki.CertBundle{CertPEM: caCertPEM, KeyPEM: caKeyPEM}

			// Generate client cert
			validity := time.Duration(validityDays) * 24 * time.Hour
			clientBundle, err := pki.GenerateClientCert(ca, name, validity)
			if err != nil {
				return fmt.Errorf("generating client certificate: %w", err)
			}

			// Write output
			if outputDir == "" {
				outputDir = pkiDir
			}
			if err := os.MkdirAll(outputDir, 0700); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}

			certPath := filepath.Join(outputDir, name+".crt")
			keyPath := filepath.Join(outputDir, name+".key")

			if err := os.WriteFile(certPath, clientBundle.CertPEM, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(keyPath, clientBundle.KeyPEM, 0600); err != nil {
				return err
			}

			fmt.Printf("Client certificate generated for operator: %s\n", name)
			fmt.Printf("  Certificate: %s\n", certPath)
			fmt.Printf("  Key:         %s\n", keyPath)
			fmt.Printf("  CA:          %s\n", filepath.Join(pkiDir, "ca.crt"))
			fmt.Printf("\nOperator needs: %s.crt, %s.key, ca.crt\n", name, name)
			return nil
		},
	}

	cmd.Flags().String("pki-dir", "", "PKI directory containing CA (required)")
	cmd.Flags().String("name", "", "Operator name (required)")
	cmd.Flags().String("output", "", "Output directory for client cert (default: same as pki-dir)")
	cmd.Flags().Int("validity-days", 90, "Client certificate validity in days")

	return cmd
}

// loadPKI reads PKI materials from a directory and returns a TLS config.
func loadPKI(pkiDir string) (*grpcapi.TLSConfig, error) {
	caCertPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	serverCertPEM, err := os.ReadFile(filepath.Join(pkiDir, "server.crt"))
	if err != nil {
		return nil, fmt.Errorf("reading server cert: %w", err)
	}

	serverKeyPEM, err := os.ReadFile(filepath.Join(pkiDir, "server.key"))
	if err != nil {
		return nil, fmt.Errorf("reading server key: %w", err)
	}

	return &grpcapi.TLSConfig{
		ServerCert: &pki.CertBundle{
			CertPEM: serverCertPEM,
			KeyPEM:  serverKeyPEM,
		},
		CACertPEM: caCertPEM,
	}, nil
}
