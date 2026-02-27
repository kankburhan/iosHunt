package cmd

import (
	"encoding/json"
	"fmt"
	"ioshunt/core"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [bundle-id]",
	Short: "AI-powered vulnerability analysis of scan results",
	Long: `Sends the static analysis report to an AI model for deep vulnerability assessment.
Requires AI configuration (api_key and model). Set them with:

  ioshunt config set ai_api_key <key>
  ioshunt config set ai_model <model>

Examples:
  ioshunt analyze ai.asaren.mobile                       # analyze latest scan
  ioshunt analyze --report /path/to/report.json           # analyze specific report`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Load and validate config
		cfg, err := core.LoadConfig()
		if err != nil {
			fmt.Printf("[!] Failed to load config: %v\n", err)
			os.Exit(1)
		}

		if err := cfg.ValidateAI(); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}

		// 2. Find the report
		reportPath, _ := cmd.Flags().GetString("report")

		if reportPath == "" && len(args) == 0 {
			fmt.Println("[!] Please provide a bundle-id or --report path")
			fmt.Println("Usage: ioshunt analyze <bundle-id>")
			fmt.Println("       ioshunt analyze --report /path/to/report.json")
			os.Exit(1)
		}

		if reportPath == "" {
			// Find latest report for this bundle-id
			bundleID := args[0]
			var err error
			reportPath, err = findLatestReport(bundleID)
			if err != nil {
				fmt.Printf("[!] %v\n", err)
				os.Exit(1)
			}
		}

		fmt.Printf("[*] Loading report: %s\n", reportPath)

		// 3. Load the report
		reportData, err := os.ReadFile(reportPath)
		if err != nil {
			fmt.Printf("[!] Failed to read report: %v\n", err)
			os.Exit(1)
		}

		var report core.Report
		if err := json.Unmarshal(reportData, &report); err != nil {
			fmt.Printf("[!] Failed to parse report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] App: %s (%s)\n", report.AppInfo.Name, report.AppInfo.BundleID)
		fmt.Println("[*] Starting AI analysis...")
		fmt.Println("─────────────────────────────────────────")

		// 4. Run AI analysis
		analysis, err := core.AnalyzeWithAI(cfg, &report)
		if err != nil {
			fmt.Printf("\n[!] AI analysis failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("─────────────────────────────────────────")

		// 5. Save the analysis
		analysisDir := filepath.Dir(reportPath)
		analysisPath := filepath.Join(analysisDir, "ai_analysis.md")

		if err := core.SaveAnalysis(analysisPath, analysis); err != nil {
			fmt.Printf("[!] Failed to save analysis: %v\n", err)
		} else {
			fmt.Printf("[+] AI analysis saved to: %s\n", analysisPath)
		}
	},
}

// findLatestReport finds the most recent report.json for a given bundle-id
func findLatestReport(bundleID string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %v", err)
	}

	targetsDir := filepath.Join(homeDir, ".ioshunt", "targets", bundleID)

	if _, err := os.Stat(targetsDir); os.IsNotExist(err) {
		return "", fmt.Errorf("no scans found for %s\nRun 'ioshunt recon %s' first", bundleID, bundleID)
	}

	// List timestamp directories and sort to get latest
	entries, err := os.ReadDir(targetsDir)
	if err != nil {
		return "", fmt.Errorf("failed to read targets dir: %v", err)
	}

	// Get directories sorted by name (timestamp format ensures chronological order)
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			reportFile := filepath.Join(targetsDir, e.Name(), "report.json")
			if _, err := os.Stat(reportFile); err == nil {
				dirs = append(dirs, e.Name())
			}
		}
	}

	if len(dirs) == 0 {
		return "", fmt.Errorf("no report.json found for %s\nRun 'ioshunt recon %s' first", bundleID, bundleID)
	}

	sort.Strings(dirs)
	latestDir := dirs[len(dirs)-1]

	return filepath.Join(targetsDir, latestDir, "report.json"), nil
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().String("report", "", "Path to a specific report.json file")
}
