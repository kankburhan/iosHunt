package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kankburhan/iosHunt/core"

	"github.com/spf13/cobra"
)

var autohuntCmd = &cobra.Command{
	Use:   "autohunt [bundle-id]",
	Short: "Full autonomous pentest: recon -> live verify -> on-device repro -> evidence",
	Long: `End-to-end pipeline that:
  1. Runs static analysis (recon)
  2. Actively verifies findings against live services
  3. Reproduces issues on the connected (non-JB) device via Frida
  4. Captures evidence (logs, screenshots, pcaps if --netcap)
  5. Bundles all evidence into a tar.gz

Optional flags let you skip phases or limit by severity.

PRECONDITIONS for full coverage:
  - device connected & paired (sideload pair)
  - patched/resigned IPA installed (root pipeline or sideload install)
  - frida CLI available locally`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bundleID := args[0]
		minSev, _ := cmd.Flags().GetString("severity")
		dur, _ := cmd.Flags().GetInt("duration")
		skipRecon, _ := cmd.Flags().GetBool("skip-recon")
		skipLive, _ := cmd.Flags().GetBool("skip-live")
		skipRepro, _ := cmd.Flags().GetBool("skip-repro")
		netcap, _ := cmd.Flags().GetBool("netcap")
		udid, _ := cmd.Flags().GetString("device")

		// ─── Phase 1: Recon ────────────────────────────────────────────────────
		var report *core.Report
		var reportPath string

		if !skipRecon {
			fmt.Println("\n=== Phase 1: Static Recon ===")
			t, err := core.NewTarget(bundleID)
			if err != nil {
				fmt.Println("[!] target init:", err)
				os.Exit(1)
			}
			ipaPath := findOrDownload(bundleID)
			if ipaPath == "" {
				fmt.Println("[!] No IPA available")
				os.Exit(1)
			}
			t.IPAPath = ipaPath
			extractDir := filepath.Join(t.WorkDir, "extracted")
			_ = os.MkdirAll(extractDir, 0755)
			if err := core.UnzipIPA(ipaPath, extractDir); err != nil {
				fmt.Println("[!] unzip:", err)
				os.Exit(1)
			}
			appPath, err := core.FindAppDirectory(extractDir)
			if err != nil {
				fmt.Println("[!] app dir:", err)
				os.Exit(1)
			}
			t.AppPath = appPath

			var patterns map[string]*regexp.Regexp
			if home, err := os.UserHomeDir(); err == nil {
				if p, err := core.LoadPatterns(filepath.Join(home, ".ioshunt", "templates", "templates")); err == nil {
					patterns = p
				}
			}
			if err := core.StaticAnalyze(t, patterns); err != nil {
				fmt.Println("[!] analyze:", err)
				os.Exit(1)
			}
			reportPath = filepath.Join(t.WorkDir, "report.json")
			_ = t.Report.SaveJSON(reportPath)
			report = t.Report
			fmt.Printf("[+] recon complete -> %s\n", reportPath)
		} else {
			r, p, err := loadLatestReport(bundleID)
			if err != nil {
				fmt.Println("[!]", err)
				os.Exit(1)
			}
			report = r
			reportPath = p
		}

		// Build candidate findings list
		all := flattenForCmd(report)
		fmt.Printf("[*] Total findings: %d\n", len(all))

		collector := core.NewEvidenceCollector("")

		// ─── Phase 2: Live Verify ──────────────────────────────────────────────
		if !skipLive {
			fmt.Println("\n=== Phase 2: Live Verification ===")
			var cand []*core.Finding
			for _, f := range all {
				if !severityMeets(f.Severity, minSev) {
					continue
				}
				if f.Value == "" && !strings.Contains(strings.ToLower(f.Title), "url") && !strings.Contains(strings.ToLower(f.Title), "ats") {
					continue
				}
				cand = append(cand, f)
			}
			if len(cand) > 0 {
				tester := core.NewLiveTester(filepath.Join(collector.OutputDir, "livetest"))
				results := tester.VerifyAll(cand)
				conf := 0
				for _, r := range results {
					if r.Status == "CONFIRMED" {
						conf++
					}
				}
				fmt.Printf("[+] verified %d findings — %d CONFIRMED\n", len(results), conf)
			} else {
				fmt.Println("[*] no candidates for live verification")
			}
		}

		// Optional netcap
		var netHandle *core.NetCaptureHandle
		if netcap && !skipRepro {
			if udid == "" {
				if devs, err := core.ListSideloadDevices(); err == nil && len(devs) > 0 {
					udid = devs[0].UDID
				}
			}
			if udid != "" {
				h, err := collector.StartNetworkCapture("autohunt-netcap", udid)
				if err != nil {
					fmt.Println("[!] netcap start failed:", err)
				} else {
					netHandle = h
					fmt.Println("[+] netcap started:", h.PcapPath)
				}
			}
		}

		// ─── Phase 3: On-Device Reproduction ───────────────────────────────────
		if !skipRepro {
			fmt.Println("\n=== Phase 3: Dynamic Reproduction ===")
			var targets []*core.Finding
			for _, f := range all {
				if severityMeets(f.Severity, minSev) {
					targets = append(targets, f)
				}
			}
			fmt.Printf("[*] reproducing %d findings (~%ds each)\n", len(targets), dur)
			engine := core.NewReproEngine(bundleID, collector)
			engine.Duration = time.Duration(dur) * time.Second
			results := engine.ReproduceAll(targets)
			conf := 0
			for _, r := range results {
				if r.Reproduced {
					conf++
				}
			}
			fmt.Printf("[+] reproduced %d / %d\n", conf, len(results))
		}

		if netHandle != nil {
			_ = netHandle.Stop()
			fmt.Println("[+] netcap saved:", netHandle.PcapPath)
		}

		// ─── Phase 4: Persist & Bundle ─────────────────────────────────────────
		_ = saveReport(report, reportPath)
		bundle, err := collector.BundleSession()
		if err == nil {
			fmt.Println("\n=== Evidence Bundle ===")
			fmt.Println("  ", bundle)
		}

		// ─── Phase 5: Final Summary ────────────────────────────────────────────
		verified := 0
		reproduced := 0
		for _, f := range all {
			if f.LiveVerified {
				verified++
			}
			if f.Reproduced {
				reproduced++
			}
		}
		fmt.Println("\n=== Summary ===")
		fmt.Printf("  total findings: %d\n", len(all))
		fmt.Printf("  live-verified : %d\n", verified)
		fmt.Printf("  reproduced    : %d\n", reproduced)
		fmt.Printf("  report        : %s\n", reportPath)
	},
}

func init() {
	rootCmd.AddCommand(autohuntCmd)
	autohuntCmd.Flags().StringP("severity", "s", "HIGH", "Min severity")
	autohuntCmd.Flags().IntP("duration", "d", 20, "Per-script repro duration (sec)")
	autohuntCmd.Flags().Bool("skip-recon", false, "Reuse existing recon report")
	autohuntCmd.Flags().Bool("skip-live", false, "Don't probe live endpoints")
	autohuntCmd.Flags().Bool("skip-repro", false, "Don't run on-device reproduction")
	autohuntCmd.Flags().Bool("netcap", false, "Capture pcap during reproduction (requires rvictl)")
	autohuntCmd.Flags().StringP("device", "u", "", "Device UDID for repro/netcap")
}

// findOrDownload tries to find a local IPA, then falls back to App Store download
func findOrDownload(bundleID string) string {
	matches, _ := filepath.Glob("*.ipa")
	for _, m := range matches {
		if strings.Contains(m, bundleID) {
			return m
		}
	}
	if err := core.DownloadIPA(bundleID, "US"); err != nil {
		return ""
	}
	matches, _ = filepath.Glob("*.ipa")
	for _, m := range matches {
		if strings.Contains(m, bundleID) {
			return m
		}
	}
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return ""
}
