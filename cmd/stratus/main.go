// STRATUS — AWS Adversary Emulation & Security Testing Framework
// Authorized security testing use only.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/cmd/stratus/cli"
)

var version = "0.1.0-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "stratus",
		Short: "STRATUS — AWS Adversary Emulation & Security Testing Framework",
		Long: `STRATUS is an operator-focused framework for authorized AWS security testing
and adversary emulation. It provides centralized identity management, permission
intelligence, modular attack operations, and team collaboration.

For authorized engagements only.`,
		Version: version,
		SilenceUsage: true,
	}

	// Register command groups
	cli.RegisterWorkspaceCommands(rootCmd)
	cli.RegisterIdentityCommands(rootCmd)
	cli.RegisterSessionCommands(rootCmd)
	cli.RegisterPivotCommands(rootCmd)
	cli.RegisterModuleCommands(rootCmd)
	cli.RegisterScopeCommands(rootCmd)
	cli.RegisterArtifactCommands(rootCmd)
	cli.RegisterNoteCommands(rootCmd)
	cli.RegisterExportCommands(rootCmd)
	cli.RegisterAWSCommands(rootCmd)
	cli.RegisterAWSRawCommands(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
