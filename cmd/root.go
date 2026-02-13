package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ioshunt/core"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ioshunt [bundle-id]",
	Short: "One command iOS pentesting pipeline",
	Long: `iOSHunt is a CLI tool to automate iOS application pentesting setup.
It handles downloading IPA, injecting Frida gadgets, resigning, installing,
and setting up the runtime environment.`,
	Args: cobra.MaximumNArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip update check for update command itself or if offline flag is set (if we had one)
		if cmd.Name() != "update" && cmd.Name() != "completion" {
			go core.CheckUpdate()
		}

		// Banner
		fmt.Println(`
    _       _____  __  __            _   
   (_)___  / ___/ / / / /_  ______  / |_ 
  / / __ \ \__ \ / /_/ / / / / __ \/ __/
 / / /_/ /___/ // __  / /_/ / / / / /_  
/_/\____//____//_/ /_/\__,_/_/ /_/\__/  
                                         
   One command iOS pentesting pipeline                                      
		`)

		// Initialize and check dependencies
		dm := core.NewDependencyManager()
		if err := dm.CheckAndInstall(); err != nil {
			fmt.Printf("Dependency check failed: %v\n", err)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}

		bundleID := args[0]
		fmt.Printf("\n[*] Starting pipeline for: %s\n", bundleID)

		// 0. Check if we should skip download
		// For now, simple logic: if skipDownload var (from downloadCmd) is used, we need to move it to valid scope or duplicate
		// Let's add local flag check or just check if file exists and ask? No, CLI should be non-interactive ideally or explicit.
		// Let's rely on finding IPA if download fails?
		// Or better: Try download. If it fails, check if we have a valid IPA.

		// 1. Download
		// TODO: Get country code from flag if promoted to root or persistent
		country := "US" // Default
		if err := core.DownloadIPA(bundleID, country); err != nil {
			fmt.Printf("[!] Download attempt failed: %v\n", err)
			// Check if we have an IPA anyway?
			matches, _ := filepath.Glob("*.ipa")
			if len(matches) > 0 {
				fmt.Println("[*] Found existing IPA, proceeding despite download failure.")
			} else {
				os.Exit(1)
			}
		}

		// 2. Unzip & Locate App
		// Find the most recent IPA or matches bundle ID in current directory
		matches, _ := filepath.Glob("*.ipa")
		var ipaPath string

		// Prioritize file containing bundleID
		for _, m := range matches {
			if strings.Contains(m, bundleID) {
				ipaPath = m
				break
			}
		}
		// Fallback to latest/last if not found (or if bundleID in filename is different format)
		if ipaPath == "" && len(matches) > 0 {
			ipaPath = matches[len(matches)-1]
		}

		if ipaPath != "" {
			fmt.Printf("[*] Found IPA: %s\n", ipaPath)
		} else {
			fmt.Println("[!] IPA not found after download.")
			os.Exit(1)
		}

		tmpDir, _ := os.MkdirTemp("", "ioshunt_pipeline_*")
		// defer os.RemoveAll(tmpDir) // Keep for debugging

		if err := core.UnzipIPA(ipaPath, tmpDir); err != nil {
			fmt.Printf("[!] Unzip failed: %v\n", err)
			os.Exit(1)
		}

		appPath, err := core.FindAppDirectory(tmpDir)
		if err != nil {
			fmt.Printf("[!] App directory not found: %v\n", err)
			os.Exit(1)
		}

		// 3. Inject
		dm := core.NewDependencyManager()
		gadgetPath := filepath.Join(dm.BinDir, "FridaGadget.dylib")
		if err := core.InjectGadget(appPath, gadgetPath); err != nil {
			fmt.Printf("[!] Injection failed: %v\n", err)
			os.Exit(1)
		}

		// 4. Resign
		// Using "Apple Development" auto-detect via FindSigningIdentity inside ResignApp logic if empty
		if err := core.ResignApp(appPath, ""); err != nil {
			fmt.Printf("[!] Resign failed: %v\n", err)
			fmt.Println("[!] Proceeding anyway (might fail install)...")
		}

		// 5. Install
		// Device ID optional
		if err := core.InstallApp(appPath, ""); err != nil {
			fmt.Printf("[!] Install failed: %v\n", err)
			fmt.Println("[!] Stopping pipeline here.")
			os.Exit(1)
		}

		// 6. Launch & Attach
		// Assuming install launches or we launch separately.
		// core.LaunchApp(appPath, "")

		// Attach
		scriptPath, _ := core.GetAssetScript("ssl_bypass.js")
		if err := core.AttachToApp(bundleID, scriptPath); err != nil {
			fmt.Printf("[!] Attach failed: %v\n", err)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags can be defined here
}
