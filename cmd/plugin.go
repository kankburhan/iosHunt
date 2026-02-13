package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage custom Frida scripts (plugins)",
	Long:  `List and manage custom Frida scripts stored in ~/.ioshunt/plugins`,
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available plugins",
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, _ := os.UserHomeDir()
		pluginDir := filepath.Join(homeDir, ".ioshunt", "plugins")

		// Create if it doesn't exist
		if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
			os.MkdirAll(pluginDir, 0755)
			fmt.Printf("[*] Created plugin directory: %s\n", pluginDir)
			fmt.Println("[*] Drop your .js Frida scripts here.")
			return
		}

		files, err := ioutil.ReadDir(pluginDir)
		if err != nil {
			fmt.Printf("[!] Failed to read plugins: %v\n", err)
			return
		}

		fmt.Printf("[*] Plugins in %s:\n", pluginDir)
		count := 0
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".js" {
				fmt.Printf("  - %s\n", f.Name())
				count++
			}
		}
		if count == 0 {
			fmt.Println("  (No plugins found)")
		}
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(pluginListCmd)
}
