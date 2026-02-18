// Package config manages STRATUS global and workspace-level configuration.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	ConfigDirName   = ".stratus"
	ConfigFileName  = "config.json"
	DefaultLogLevel = "info"
)

// GlobalConfig holds user-level configuration for the STRATUS CLI.
type GlobalConfig struct {
	DefaultRegion     string `json:"default_region"`
	LogLevel          string `json:"log_level"`
	ActiveWorkspace   string `json:"active_workspace"`    // UUID of last-used workspace
	WorkspacesDir     string `json:"workspaces_dir"`      // Base directory for workspaces
	SecretMode        string `json:"secret_mode"`         // vault | os_keystore | memory_only
	AutoRefresh       bool   `json:"auto_refresh"`        // Auto-refresh expiring sessions
	PluginDirs        []string `json:"plugin_dirs"`
	TrustStoreKeys    []string `json:"trust_store_keys"`  // Ed25519 public keys for module verification
}

// WorkspaceConfig holds per-workspace settings.
type WorkspaceConfig struct {
	AutoRefresh           bool   `json:"auto_refresh"`
	StaleThresholdHours   int    `json:"stale_threshold_hours"`
	DefaultConcurrency    int    `json:"default_concurrency"`
	RateLimitPerService   int    `json:"rate_limit_per_service"` // req/s
	CacheTTLSeconds       int    `json:"cache_ttl_seconds"`
	RequireConfirmWrite   bool   `json:"require_confirm_write"`
	RequireConfirmDestroy bool   `json:"require_confirm_destroy"`
}

// DefaultGlobalConfig returns sensible defaults.
func DefaultGlobalConfig() GlobalConfig {
	home, _ := os.UserHomeDir()
	return GlobalConfig{
		DefaultRegion: "us-east-1",
		LogLevel:      DefaultLogLevel,
		WorkspacesDir: filepath.Join(home, ConfigDirName, "workspaces"),
		SecretMode:    "vault",
		AutoRefresh:   false,
		PluginDirs:    []string{filepath.Join(home, ConfigDirName, "plugins")},
	}
}

// DefaultWorkspaceConfig returns sensible workspace defaults.
func DefaultWorkspaceConfig() WorkspaceConfig {
	return WorkspaceConfig{
		AutoRefresh:           false,
		StaleThresholdHours:   24,
		DefaultConcurrency:    10,
		RateLimitPerService:   10,
		CacheTTLSeconds:       300,
		RequireConfirmWrite:   true,
		RequireConfirmDestroy: true,
	}
}

// ConfigDir returns the global STRATUS config directory path.
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ConfigDirName)
}

// LoadGlobalConfig loads the global config from ~/.stratus/config.json.
func LoadGlobalConfig() (GlobalConfig, error) {
	path := filepath.Join(ConfigDir(), ConfigFileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultGlobalConfig(), nil
		}
		return GlobalConfig{}, err
	}

	cfg := DefaultGlobalConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return GlobalConfig{}, err
	}
	return cfg, nil
}

// SaveGlobalConfig persists the global config to ~/.stratus/config.json.
func SaveGlobalConfig(cfg GlobalConfig) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, ConfigFileName), data, 0600)
}
