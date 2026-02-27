package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage iOSHunt configuration",
	Long: `Manage iOSHunt configuration including AI provider settings.

Examples:
  ioshunt config show
  ioshunt config set ai_api_key sk-xxxx
  ioshunt config set ai_model gpt-4o
  ioshunt config set ai_base_url https://api.openai.com/v1`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := core.LoadConfig()
		if err != nil {
			fmt.Printf("[!] Failed to load config: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("┌─────────────────────────────────────────────┐")
		fmt.Println("│          iOSHunt Configuration               │")
		fmt.Println("├─────────────────────────────────────────────┤")

		// Mask API key
		apiKey := cfg.AIAPIKey
		if apiKey != "" {
			if len(apiKey) > 8 {
				apiKey = apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
			} else {
				apiKey = "****"
			}
		} else {
			apiKey = "(not set)"
		}

		model := cfg.AIModel
		if model == "" {
			model = "(not set)"
		}

		provider := cfg.AIProvider
		if provider == "" {
			provider = "(auto)"
		}

		fmt.Printf("│  AI Provider:  %-28s │\n", provider)
		fmt.Printf("│  AI Base URL:  %-28s │\n", cfg.AIBaseURL)
		fmt.Printf("│  AI API Key:   %-28s │\n", apiKey)
		fmt.Printf("│  AI Model:     %-28s │\n", model)
		fmt.Println("└─────────────────────────────────────────────┘")
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value. Available keys:

  ai_api_key    - API key for the AI provider (required for analyze)
  ai_model      - AI model name (required for analyze)
  ai_base_url   - OpenAI-compatible API base URL
  ai_provider   - Provider label (openai, gemini, ollama, groq)

Preset shortcuts for ai_base_url:
  openai   → https://api.openai.com/v1
  gemini   → https://generativelanguage.googleapis.com/v1beta/openai
  ollama   → http://localhost:11434/v1
  groq     → https://api.groq.com/openai/v1`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := strings.ToLower(args[0])
		value := args[1]

		cfg, err := core.LoadConfig()
		if err != nil {
			fmt.Printf("[!] Failed to load config: %v\n", err)
			os.Exit(1)
		}

		switch key {
		case "ai_api_key":
			cfg.AIAPIKey = value
		case "ai_model":
			cfg.AIModel = value
		case "ai_base_url":
			cfg.AIBaseURL = value
		case "ai_provider":
			cfg.AIProvider = value
			// Auto-set base URL for known providers
			switch strings.ToLower(value) {
			case "openai":
				cfg.AIBaseURL = "https://api.openai.com/v1"
			case "gemini":
				cfg.AIBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai"
			case "ollama":
				cfg.AIBaseURL = "http://localhost:11434/v1"
			case "groq":
				cfg.AIBaseURL = "https://api.groq.com/openai/v1"
			}
		default:
			fmt.Printf("[!] Unknown config key: %s\n", key)
			fmt.Println("Available keys: ai_api_key, ai_model, ai_base_url, ai_provider")
			os.Exit(1)
		}

		if err := core.SaveConfig(cfg); err != nil {
			fmt.Printf("[!] Failed to save config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Set %s successfully.\n", key)

		// Show helpful follow-up messages
		if key == "ai_provider" {
			fmt.Printf("[*] Base URL auto-set to: %s\n", cfg.AIBaseURL)
		}
		if key == "ai_api_key" {
			if cfg.AIModel == "" {
				fmt.Println("[*] Next: Set your model with: ioshunt config set ai_model <model>")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
}
