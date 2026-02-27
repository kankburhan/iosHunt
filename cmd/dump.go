package cmd

import (
	"fmt"
	"ioshunt/core"

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
	// Auto-detect device
	device, err := core.GetConnectedDevice()
	if err != nil {
		fmt.Printf("[!] Warning: %v. Assuming remote/TCP or relying on Frida's auto-detection.\n", err)
	} else {
		fmt.Printf("[*] Detected USB Device: %s (%s)\n", device.Name, device.ID)
	}

	fmt.Printf("[*] Dumping %s from %s...\n", scriptName, bundleID)

	script, err := core.GetAssetScript(scriptName)
	if err != nil {
		fmt.Printf("[!] Failed to load script: %v\n", err)
		return
	}

	// Dump is interactive usually
	if err := core.AttachToApp(bundleID, script); err != nil {
		fmt.Printf("[!] Failed to attach: %v\n", err)
	}
}
