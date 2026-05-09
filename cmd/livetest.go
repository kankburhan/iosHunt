package cmd

import (
	"fmt"
	"os"
	"strings"

	"ioshunt/core"

	"github.com/spf13/cobra"
)

var livetestCmd = &cobra.Command{
	Use:   "livetest [bundle-id]",
	Short: "Actively verify findings against live services (API keys, URLs, ATS)",
	Long: `Probes findings from a recon scan against live services to confirm exploitability.

Validates:
  - API keys by hitting real provider endpoints (Google, Stripe, GitHub, Slack, Mapbox, SendGrid, OpenAI, Firebase)
  - URL endpoints for accessibility / open admin panels
  - ATS bypass via plaintext HTTP fetches

ACTIVE TESTING — only run on targets you are authorized to assess.
Updates report.json with LiveStatus / LiveVerified / Evidence fields.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bundleID := args[0]
		minSev, _ := cmd.Flags().GetString("severity")
		max, _ := cmd.Flags().GetInt("max")
		outDir, _ := cmd.Flags().GetString("output-dir")
		dry, _ := cmd.Flags().GetBool("dry-run")

		report, path, err := loadLatestReport(bundleID)
		if err != nil {
			fmt.Println("[!]", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded report: %s\n", path)

		// Build verifiable list
		var candidates []*core.Finding
		all := flattenForCmd(report)
		for _, f := range all {
			if !severityMeets(f.Severity, minSev) {
				continue
			}
			if f.Value == "" && !strings.Contains(strings.ToLower(f.Title), "url") && !strings.Contains(strings.ToLower(f.Title), "ats") {
				continue
			}
			candidates = append(candidates, f)
			if len(candidates) >= max {
				break
			}
		}
		if len(candidates) == 0 {
			fmt.Println("[*] No findings eligible for live verification.")
			return
		}

		fmt.Printf("[*] Verifying %d finding(s) >= %s ...\n", len(candidates), minSev)
		tester := core.NewLiveTester(outDir)
		tester.DryRun = dry
		results := tester.VerifyAll(candidates)

		_ = saveReport(report, path)
		_, _ = tester.SaveResults(results)

		conf := 0
		for _, r := range results {
			mark := "·"
			if r.Status == "CONFIRMED" {
				conf++
				mark = "[!]"
			}
			fmt.Printf("  %s [%s] %s — %s\n", mark, r.Status, r.Provider, truncCmd(r.Detail, 120))
		}
		fmt.Printf("\n[+] Done. %d/%d CONFIRMED. Evidence dir: %s\n", conf, len(results), tester.OutputDir)
	},
}

func init() {
	rootCmd.AddCommand(livetestCmd)
	livetestCmd.Flags().StringP("severity", "s", "HIGH", "Minimum severity to verify")
	livetestCmd.Flags().IntP("max", "m", 30, "Max findings to probe")
	livetestCmd.Flags().StringP("output-dir", "o", "", "Where to save evidence")
	livetestCmd.Flags().Bool("dry-run", false, "Print plan without making requests")
}

func severityMeets(actual, minimum string) bool {
	order := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}
	return order[strings.ToUpper(actual)] >= order[strings.ToUpper(minimum)]
}

func truncCmd(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// flattenForCmd flattens findings across categories into pointers
func flattenForCmd(r *core.Report) []*core.Finding {
	var out []*core.Finding
	cats := []struct {
		name string
		s    *[]core.Finding
	}{
		{"secret", &r.Findings.Secrets},
		{"hardening", &r.Findings.HardeningIssues},
		{"storage", &r.Findings.InsecureStorage},
		{"crypto", &r.Findings.CryptoIssues},
		{"code", &r.Findings.CodeIssues},
	}
	for _, c := range cats {
		for i := range *c.s {
			f := &(*c.s)[i]
			if f.Category == "" {
				f.Category = c.name
			}
			if f.ID == "" {
				f.ID = core.ComputeFindingID(f)
			}
			out = append(out, f)
		}
	}
	return out
}
