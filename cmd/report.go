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

var reportFormat string

var reportCmd = &cobra.Command{
	Use:   "report <bundle_id>",
	Short: "Generate reports from existing scan data",
	Args:  cobra.ExactArgs(1),
	Run:   runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&reportFormat, "format", "html", "Output format (html, md)")
}

func runReport(cmd *cobra.Command, args []string) {
	bundleID := args[0]
	fmt.Printf("[*] Generating report for: %s\n", bundleID)

	// 1. Find latest workspace for bundleID
	homeDir, _ := os.UserHomeDir()
	targetDir := filepath.Join(homeDir, ".ioshunt", "targets", bundleID)

	entries, err := os.ReadDir(targetDir)
	if err != nil || len(entries) == 0 {
		fmt.Printf("[!] No scan data found for %s in %s\n", bundleID, targetDir)
		return
	}

	// Sort by Name (timestamp) desc
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})

	latestScan := entries[0].Name()
	scanDir := filepath.Join(targetDir, latestScan)
	jsonPath := filepath.Join(scanDir, "report.json")

	fmt.Printf("[*] Using scan data from: %s\n", latestScan)

	// 2. Load JSON
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("[!] Failed to read report.json: %v\n", err)
		return
	}

	var report core.Report
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Printf("[!] Failed to parse report.json: %v\n", err)
		return
	}

	// 3. Render output
	switch reportFormat {
	case "html":
		outPath := filepath.Join(scanDir, "report.html")
		if err := report.SaveHTML(outPath); err != nil {
			fmt.Printf("[!] Failed to generate HTML: %v\n", err)
			return
		}
		fmt.Printf("[+] HTML Report saved to: %s\n", outPath)
		fmt.Printf("[*] Try: open %s\n", outPath)
	case "md":
		outPath := filepath.Join(scanDir, "report.md")
		if err := report.SaveMarkdown(outPath); err != nil {
			fmt.Printf("[!] Failed to generate Markdown: %v\n", err)
			return
		}
		fmt.Printf("[+] Markdown Report saved to: %s\n", outPath)
	default:
		fmt.Println("[!] Unsupported format. Use --format html or --format md")
	}
}
