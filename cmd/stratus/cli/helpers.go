package cli

import (
	"fmt"
	"os"

	"github.com/stratus-framework/stratus/internal/config"
	"github.com/stratus-framework/stratus/internal/core"
	"golang.org/x/term"
)

// loadActiveEngine opens the currently active workspace engine.
// Prompts for the vault passphrase.
func loadActiveEngine() (*core.Engine, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	if cfg.ActiveWorkspace == "" {
		return nil, fmt.Errorf("no active workspace; use 'stratus workspace new' or 'stratus workspace use <name>'")
	}

	// Find workspace path
	wsPath := ""
	entries, err := os.ReadDir(cfg.WorkspacesDir)
	if err != nil {
		return nil, fmt.Errorf("reading workspaces directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() == cfg.ActiveWorkspace {
			wsPath = cfg.WorkspacesDir + "/" + entry.Name()
			break
		}
	}

	if wsPath == "" {
		return nil, fmt.Errorf("workspace directory not found for: %s", cfg.ActiveWorkspace)
	}

	// Prompt for passphrase
	fmt.Fprint(os.Stderr, "Vault passphrase: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	engine, err := core.OpenWorkspace(wsPath, string(passBytes))
	if err != nil {
		return nil, fmt.Errorf("opening workspace: %w", err)
	}

	return engine, nil
}
