package cmd

import (
	"fmt"
	"ioshunt/core"
	"path/filepath"

	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump analyzed data or forensic artifacts",
}

var dumpKeychainCmd = &cobra.Command{
	Use:   "keychain <bundle_id>",
	Short: "Dump Keychain items (requires active app)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runDumpScript(args[0], "keychain_dump.js")
	},
}

var dumpDefaultsCmd = &cobra.Command{
	Use:   "defaults <bundle_id>",
	Short: "Dump NSUserDefaults",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runDumpScript(args[0], "defaults_dump.js")
	},
}

var dumpCookiesCmd = &cobra.Command{
	Use:   "cookies <bundle_id>",
	Short: "Dump Cookies",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runDumpScript(args[0], "cookies_dump.js")
	},
}

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.AddCommand(dumpKeychainCmd)
	dumpCmd.AddCommand(dumpDefaultsCmd)
	dumpCmd.AddCommand(dumpCookiesCmd)
}

func runDumpScript(bundleID string, scriptName string) {
	fmt.Printf("[*] Dumping %s from %s...\n", scriptName, bundleID)

	script, err := core.GetAssetScript(filepath.Join("assets", scriptName))
	if err != nil {
		fmt.Printf("[!] Failed to load script: %v\n", err)
		return
	}

	// Dump is interactive usually
	if err := core.AttachToApp(bundleID, script); err != nil {
		fmt.Printf("[!] Failed to attach: %v\n", err)
	}
}
