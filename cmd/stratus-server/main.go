// stratus-server is the teamserver binary for multi-operator STRATUS engagements.
// It exposes the same internal gRPC API with RBAC and mTLS transport.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/grpcapi"
)

var version = "0.1.0-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "stratus-server",
		Short:   "STRATUS Teamserver — multi-operator collaboration server",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			fmt.Printf("STRATUS Teamserver starting on %s\n", addr)

			server, err := grpcapi.NewTCPServer(addr)
			if err != nil {
				return fmt.Errorf("starting server: %w", err)
			}

			// Handle graceful shutdown
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

	rootCmd.Flags().String("addr", ":50051", "Server listen address")
	rootCmd.Flags().String("config", "", "Path to server config file")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
