package cmd

import (
	"fmt"
	"github.com/kankburhan/iosHunt/core"

	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for Claude Desktop AI auto-pentest",
	Long: `Starts an MCP (Model Context Protocol) server over stdio.
Connect this to Claude Desktop or any MCP-compatible AI client to enable
autonomous iOS penetration testing.

Claude Desktop Configuration (~/.claude/claude_desktop_config.json):

  {
    "mcpServers": {
      "ioshunt": {
        "command": "ioshunt",
        "args": ["mcp"]
      }
    }
  }

The AI agent will have access to all iOSHunt tools:
  - ios_recon: Full 26-phase static analysis
  - ios_download_ipa: App Store IPA download
  - ios_get_findings: Query findings by category/severity
  - ios_get_app_info: App metadata and binary security
  - ios_generate_frida_script: AI-generated Frida scripts
  - ios_attach_frida: Runtime instrumentation
  - ios_dump_runtime: Keychain/cookies/defaults extraction
  - ios_check_device: Device connectivity check
  - ios_generate_report: Multi-format report generation
  - ios_inject_and_resign: Frida gadget injection
  - ios_install_app: Device installation
  - ios_pentest_status: Session status and next actions
  - ios_search_strings: Pattern search in app binaries
  - ios_exploit_verify: Exploitability verification

Example Usage with Claude Desktop:
  "Perform a full security assessment of com.example.app"
  "Find all hardcoded API keys and verify if they are live"
  "Generate a Frida script to bypass certificate pinning"
  "Create a pentest report with all critical findings"`,
	Run: func(cmd *cobra.Command, args []string) {
		server := core.NewMCPServer()

		if err := server.Run(); err != nil {
			fmt.Printf("[!] MCP server error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
