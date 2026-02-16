package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ioshunt/core"

	"github.com/spf13/cobra"
)

var reconCmd = &cobra.Command{
	Use:   "recon [bundle-id]",
	Short: "Perform static analysis on an IPA",
	Long: `Downloads (if needed) and statically analyzes an IPA for sensitive information 
like URLs, API keys, emails, and IP addresses.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}

		bundleID := args[0]
		fmt.Printf("[*] Starting Recon for: %s\n", bundleID)

		// Prepare Target Context using Phase 8 architecture
		target, err := core.NewTarget(bundleID)
		if err != nil {
			fmt.Printf("[!] Failed to initialize target context: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Workspace: %s\n", target.WorkDir)

		// 1. Download (reuse logic from root or duplicate for now)
		// For recon, we might just want to analyze a local IPA if available
		// Check for existing IPA first
		matches, _ := filepath.Glob("*.ipa")
		var ipaPath string
		foundLocal := false

		// Prioritize file containing bundleID
		for _, m := range matches {
			if strings.Contains(m, bundleID) {
				ipaPath = m
				foundLocal = true
				break
			}
		}

		if !foundLocal {
			fmt.Println("[*] IPA not found locally. Attempting download...")
			country := "US"
			if err := core.DownloadIPA(bundleID, country); err != nil {
				fmt.Printf("[!] Download failed: %v\n", err)
				os.Exit(1)
			}
			// Find again
			matches, _ = filepath.Glob("*.ipa")
			for _, m := range matches {
				if strings.Contains(m, bundleID) {
					ipaPath = m
					break
				}
			}
			if ipaPath != "" {
				target.IPAPath = ipaPath // Update context
			}
		} else {
			fmt.Printf("[*] Using existing IPA: %s\n", ipaPath)
			target.IPAPath = ipaPath
		}

		if target.IPAPath == "" {
			fmt.Println("[!] Could not locate IPA.")
			os.Exit(1)
		}

		// 2. Unzip
		// Use target.WorkDir/extracted as temp dir
		extractDir := filepath.Join(target.WorkDir, "extracted")
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			fmt.Printf("[!] Failed to create extract dir: %v\n", err)
			os.Exit(1)
		}

		if err := core.UnzipIPA(target.IPAPath, extractDir); err != nil {
			fmt.Printf("[!] Unzip failed: %v\n", err)
			os.Exit(1)
		}

		appPath, err := core.FindAppDirectory(extractDir)
		if err != nil {
			fmt.Printf("[!] App directory not found: %v\n", err)
			os.Exit(1)
		}
		target.AppPath = appPath

		// Load external patterns
		var externalPatterns map[string]*regexp.Regexp

		homeDir, _ := os.UserHomeDir()
		// Load from default templates dir recursively
		templatesDir := filepath.Join(homeDir, ".ioshunt", "templates", "templates") // gosek-templates structure
		if patterns, err := core.LoadPatterns(templatesDir); err == nil && len(patterns) > 0 {
			fmt.Printf("[*] Loaded %d external secret patterns\n", len(patterns))
			externalPatterns = patterns
		}

		// 3. Analyze
		if err := core.StaticAnalyze(target, externalPatterns); err != nil {
			fmt.Printf("[!] Analysis failed: %v\n", err)
			os.Exit(1)
		}

		// 4. Ghidra Analysis (Optional)
		ghidraPath, _ := cmd.Flags().GetString("ghidra-path")
		if ghidraPath != "" {
			fmt.Printf("[*] Ghidra path provided. Starting Advanced Static Analysis...\n")

			// Locate script (assuming existing in assets/ for dev)
			// in prod, we might need to look relative to binary or embedded
			cwd, _ := os.Getwd()
			scriptPath := filepath.Join(cwd, "assets", core.GHIDRA_SCRIPT)

			// If not found, check if it's in the same dir as binary (deployment)
			if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
				// Try looking in executable dir
				ex, err := os.Executable()
				if err == nil {
					scriptPath = filepath.Join(filepath.Dir(ex), "assets", core.GHIDRA_SCRIPT)
				}
			}

			if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
				fmt.Printf("[!] Could not locate Ghidra script %s. Skipping Ghidra analysis.\n", core.GHIDRA_SCRIPT)
			} else {
				findings, err := core.RunGhidraAnalysis(target.BinaryPath, ghidraPath, scriptPath)
				if err != nil {
					fmt.Printf("[!] Ghidra analysis failed: %v\n", err)
				} else {
					fmt.Printf("[+] Ghidra analysis completed. Found %d issues.\n", len(findings))
					for _, f := range findings {
						target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, core.Finding{
							Title:       "Ghidra Detected: " + f.Vulnerability,
							Description: f.Description,
							FilePath:    filepath.Base(target.BinaryPath),
							LineNumber:  0,
							Snippet:     fmt.Sprintf("Caller: %s @ %s", f.Caller, f.Address),
							Value:       f.Vulnerability,
						})
					}
				}
			}
		}

		// 5. Report
		// Save JSON report always
		jsonPath := filepath.Join(target.WorkDir, "report.json")
		if err := target.Report.SaveJSON(jsonPath); err != nil {
			fmt.Printf("[!] Failed to save JSON report: %v\n", err)
		} else {
			fmt.Printf("[+] JSON Report saved to: %s\n", jsonPath)
		}

		outputFile, _ := cmd.Flags().GetString("output")
		if outputFile != "" {
			if err := target.Report.SaveMarkdown(outputFile); err != nil {
				fmt.Printf("[!] Failed to write report: %v\n", err)
			} else {
				fmt.Printf("[+] Report saved to: %s\n", outputFile)
			}
		} else {
			// Auto save markdown to workspace
			mdPath := filepath.Join(target.WorkDir, "report.md")
			target.Report.SaveMarkdown(mdPath)
			fmt.Printf("[+] Markdown Report saved to: %s\n", mdPath)
		}

		// Cleanup? Workspace is persistent now based on roadmap recommendations.
		// "Determininstic Workspace Layout" -> we might keep it.
		// Let's NOT cleanup target struct WorkDir, but main temporary usage?
		// The roadmap says "Standardize Workspace Layout ... Reproducibility".
		// So we should keep the extracted files or at least the artifacts.
		// For now, let's keep it.
	},
}

func init() {
	rootCmd.AddCommand(reconCmd)
	reconCmd.Flags().StringP("output", "o", "", "Output report to file (Markdown)")
	reconCmd.Flags().String("ghidra-path", "", "Path to Ghidra installation root (for advanced analysis)")
}
