package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the iOSHunt configuration stored at ~/.ioshunt/config.json
type Config struct {
	AIProvider string `json:"ai_provider"` // label only (e.g. "openai", "gemini", "ollama")
	AIBaseURL  string `json:"ai_base_url"` // OpenAI-compatible endpoint
	AIAPIKey   string `json:"ai_api_key"`
	AIModel    string `json:"ai_model"`
}

// configPath returns the path to the config file
func configPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %v", err)
	}
	return filepath.Join(homeDir, ".ioshunt", "config.json"), nil
}

// LoadConfig loads the config from disk, returns default if not found
func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config
			return &Config{
				AIBaseURL: "https://api.openai.com/v1",
			}, nil
		}
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Set default base URL if empty
	if cfg.AIBaseURL == "" {
		cfg.AIBaseURL = "https://api.openai.com/v1"
	}

	return &cfg, nil
}

// SaveConfig saves the config to disk
func SaveConfig(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %v", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	return os.WriteFile(path, data, 0600) // 0600: private — contains API key
}

// ValidateAI checks that the required AI configuration is set
func (c *Config) ValidateAI() error {
	if c.AIAPIKey == "" {
		return fmt.Errorf("AI API key not configured. Run:\n  ioshunt config set ai_api_key <your-key>")
	}
	if c.AIModel == "" {
		return fmt.Errorf("AI model not configured. Run:\n  ioshunt config set ai_model <model-name>\n\nExamples: gpt-4o, gemini-2.0-flash, llama3")
	}
	return nil
}
