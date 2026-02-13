package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var scriptPath string

var attachCmd = &cobra.Command{
	Use:   "attach <process-name>",
	Short: "Attach Frida to a running application",
	Args:  cobra.ExactArgs(1),
	Run:   runAttach,
}

func runAttach(cmd *cobra.Command, args []string) {
	processName := args[0]
	fmt.Printf("[*] Attaching to process: %s\n", processName)

	var scripts []string

	// Flags
	if ssl, _ := cmd.Flags().GetBool("ssl"); ssl {
		if p, err := core.GetAssetScript("ssl_bypass.js"); err == nil {
			fmt.Println("[*] Loading SSL Bypass")
			scripts = append(scripts, p)
		}
	}
	if bio, _ := cmd.Flags().GetBool("bio"); bio {
		if p, err := core.GetAssetScript("bio_bypass.js"); err == nil {
			fmt.Println("[*] Loading Biometric Bypass")
			scripts = append(scripts, p)
		}
	}
	if ixguard, _ := cmd.Flags().GetBool("ixguard"); ixguard {
		if p, err := core.GetAssetScript("ixguard.js"); err == nil {
			fmt.Println("[*] Loading iXGuard Bypass")
			scripts = append(scripts, p)
		}
	}
	if monitor, _ := cmd.Flags().GetBool("monitor-api"); monitor {
		if p, err := core.GetAssetScript("api_monitor.js"); err == nil {
			fmt.Println("[*] Loading API Monitor")
			scripts = append(scripts, p)
		}
	}

	// Phase 9 Flags
	if crypto, _ := cmd.Flags().GetBool("crypto"); crypto {
		if p, err := core.GetAssetScript("crypto_monitor.js"); err == nil {
			fmt.Println("[*] Loading Crypto Monitor (Phase 9)")
			scripts = append(scripts, p)
		}
	}
	if bypass, _ := cmd.Flags().GetBool("bypass"); bypass {
		if p, err := core.GetAssetScript("bypass_universal.js"); err == nil {
			fmt.Println("[*] Loading Universal Bypass (Phase 9)")
			scripts = append(scripts, p)
		}
	}
	if headers, _ := cmd.Flags().GetBool("headers"); headers {
		if p, err := core.GetAssetScript("header_logger.js"); err == nil {
			fmt.Println("[*] Loading Header Logger (Phase 9)")
			scripts = append(scripts, p)
		}
	}

	if pluginName, _ := cmd.Flags().GetString("plugin"); pluginName != "" {
		home, _ := os.UserHomeDir()
		pluginPath := filepath.Join(home, ".ioshunt", "plugins", pluginName)
		content, err := os.ReadFile(pluginPath)
		if err == nil {
			scripts = append(scripts, string(content))
			fmt.Printf("[+] Loaded plugin: %s\n", pluginName)
		} else {
			// Try append .js
			pluginPath += ".js"
			content, err := os.ReadFile(pluginPath)
			if err == nil {
				scripts = append(scripts, string(content))
				fmt.Printf("[+] Loaded plugin: %s\n", pluginName)
			} else {
				fmt.Printf("[!] Plugin not found: %s\n", pluginName)
			}
		}
	}

	// Attach
	if err := core.AttachToApp(processName, scripts...); err != nil {
		fmt.Printf("[!] Attach failed: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(attachCmd)
	attachCmd.Flags().StringVarP(&scriptPath, "script", "s", "", "Path to custom Frida script")
	attachCmd.Flags().Bool("ssl", false, "Load SSL Pinning bypass script")
	attachCmd.Flags().Bool("bio", false, "Load Biometric (TouchID/FaceID) bypass script")
	attachCmd.Flags().Bool("monitor-api", false, "Load API Monitor (NSURLSession) script")
	attachCmd.Flags().Bool("ixguard", false, "Load iXGuard/Adanced Anti-Frida bypass script")
	attachCmd.Flags().Bool("crypto", false, "Load Crypto Monitor (Phase 9)")
	attachCmd.Flags().Bool("bypass", false, "Load Universal Bypass (Phase 9)")
	attachCmd.Flags().Bool("headers", false, "Load Header Logger (Phase 9)")
	attachCmd.Flags().String("plugin", "", "Load a plugin script by name")
}
