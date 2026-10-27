// Package config handles the small JSON configuration file used by the CLI.
//
// The configuration only stores non-sensitive defaults. The database schema
// also contains a settings table for database-internal metadata.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds user-editable defaults.
type Config struct {
	DBPath               string `json:"dbPath"`
	PollIntervalMS       int    `json:"pollIntervalMs"`
	LocalAddrRefreshSec  int    `json:"localAddrRefreshSec"`
	StoreUnattributedDNS bool   `json:"storeUnattributedDNS"`
}

// DefaultDir returns %LOCALAPPDATA%\NetTrace (or the user config dir).
func DefaultDir() string {
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		return filepath.Join(dir, "NetTrace")
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(".", "NetTrace")
	}
	return filepath.Join(dir, "NetTrace")
}

// DefaultDBPath returns the default SQLite database path.
func DefaultDBPath() string {
	return filepath.Join(DefaultDir(), "nettrace.db")
}

// DefaultPath returns the default config file path.
func DefaultPath() string {
	return filepath.Join(DefaultDir(), "config.json")
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		DBPath:               DefaultDBPath(),
		PollIntervalMS:       2000,
		LocalAddrRefreshSec:  30,
		StoreUnattributedDNS: false,
	}
}

// Load reads path, creating it with defaults when it does not exist. An empty
// path uses the default config location.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	if env := os.Getenv("NETTRACE_DB"); env != "" {
		cfg.DBPath = env
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := cfg.Save(path); err != nil {
			return cfg, fmt.Errorf("write default config: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.DBPath == "" {
		cfg.DBPath = DefaultDBPath()
	}
	if cfg.PollIntervalMS < 250 {
		cfg.PollIntervalMS = 250
	}
	if cfg.LocalAddrRefreshSec < 5 {
		cfg.LocalAddrRefreshSec = 5
	}
	return cfg, nil
}

// Save writes the configuration atomically.
func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// PollInterval returns the effective process/connection polling interval.
func (c *Config) PollInterval() time.Duration {
	d := time.Duration(c.PollIntervalMS) * time.Millisecond
	if d < 250*time.Millisecond {
		d = 250 * time.Millisecond
	}
	return d
}

// LocalAddrRefresh returns how often the local address cache is refreshed.
func (c *Config) LocalAddrRefresh() time.Duration {
	d := time.Duration(c.LocalAddrRefreshSec) * time.Second
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	return d
}
