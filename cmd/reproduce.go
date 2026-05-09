package cmd

import (
	"fmt"
	"os"
	"time"

	"ioshunt/core"

	"github.com/spf13/cobra"
)

var reproduceCmd = &cobra.Command{
	Use:   "reproduce [bundle-id]",
	Short: "Auto-reproduce static findings on the connected device via Frida hooks",
	Long: `Attaches Frida hooks tailored to each finding category to confirm
issues at runtime on a real device. Marks Finding.Reproduced=true when
runtime evidence is captured.

Categories handled:
  - secret/url    -> auto_repro_network.js (URLSession monitor)
  - keychain      -> auto_repro_keychain.js
  - storage       -> auto_repro_storage.js (NSUserDefaults / NSFileManager / fopen)
  - crypto        -> auto_repro_crypto.js (CCCrypt / CC_MD5 / etc.)
  - url_scheme    -> auto_repro_url_scheme.js (AppDelegate openURL)
  - pinning       -> ssl_bypass.js
  - jailbreak     -> bypass_universal.js

Works on non-JB devices when FridaGadget has been injected.
Make sure you've run: ioshunt inject + resign + install first.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bundleID := args[0]
		minSev, _ := cmd.Flags().GetString("severity")
		category, _ := cmd.Flags().GetString("category")
		findingID, _ := cmd.Flags().GetString("id")
		dur, _ := cmd.Flags().GetInt("duration")
		spawn, _ := cmd.Flags().GetBool("spawn")
		verbose, _ := cmd.Flags().GetBool("verbose")

		report, path, err := loadLatestReport(bundleID)
		if err != nil {
			fmt.Println("[!]", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded report: %s\n", path)

		all := flattenForCmd(report)
		var targets []*core.Finding
		switch {
		case findingID != "":
			for _, f := range all {
				if f.ID == findingID {
					targets = append(targets, f)
					break
				}
			}
		case category != "":
			for _, f := range all {
				if f.Category == category {
					targets = append(targets, f)
				}
			}
		default:
			for _, f := range all {
				if severityMeets(f.Severity, minSev) {
					targets = append(targets, f)
				}
			}
		}
		if len(targets) == 0 {
			fmt.Println("[*] No findings matched.")
			return
		}

		fmt.Printf("[*] Reproducing %d finding(s) on device — %ds per script\n", len(targets), dur)
		fmt.Println("[*] Make sure the patched app is installed and running on a connected device.")

		collector := core.NewEvidenceCollector("")
		engine := core.NewReproEngine(bundleID, collector)
		engine.Spawn = spawn
		engine.Verbose = verbose
		engine.Duration = time.Duration(dur) * time.Second
		results := engine.ReproduceAll(targets)

		_ = saveReport(report, path)

		conf := 0
		for _, r := range results {
			mark := "·"
			if r.Reproduced {
				conf++
				mark = "[!]"
			}
			fmt.Printf("  %s [%s] %-40.40s script=%s hits=%d\n", mark, r.Status, r.Title, r.Script, r.Hits)
			if r.Error != "" {
				fmt.Printf("      err: %s\n", r.Error)
			}
		}
		fmt.Printf("\n[+] %d/%d reproduced. Evidence: %s\n", conf, len(results), collector.OutputDir)
	},
}

func init() {
	rootCmd.AddCommand(reproduceCmd)
	reproduceCmd.Flags().StringP("severity", "s", "HIGH", "Minimum severity")
	reproduceCmd.Flags().StringP("category", "c", "", "Only reproduce a specific category")
	reproduceCmd.Flags().String("id", "", "Reproduce a single finding by ID")
	reproduceCmd.Flags().IntP("duration", "d", 20, "Hook duration in seconds")
	reproduceCmd.Flags().Bool("spawn", false, "Use frida -f spawn instead of attach")
	reproduceCmd.Flags().BoolP("verbose", "v", false, "Verbose")
}
