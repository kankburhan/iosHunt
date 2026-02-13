package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var injectCmd = &cobra.Command{
	Use:   "inject <ipa-path>",
	Short: "Inject Frida Gadget into an IPA",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ipaPath := args[0]

		// Temporary workspace
		tmpDir, _ := os.MkdirTemp("", "ioshunt_inject_*")
		// defer os.RemoveAll(tmpDir) // Keep for debugging or next steps in pipeline

		// 1. Unzip
		if err := core.UnzipIPA(ipaPath, tmpDir); err != nil {
			fmt.Printf("[!] Unzip failed: %v\n", err)
			os.Exit(1)
		}

		// 2. Find App
		appPath, err := core.FindAppDirectory(tmpDir)
		if err != nil {
			fmt.Printf("[!] Could not find .app: %v\n", err)
			os.Exit(1)
		}

		// 3. Inject
		// Get Gadget Path from DependencyManager
		dm := core.NewDependencyManager()
		gadgetPath := filepath.Join(dm.BinDir, "FridaGadget.dylib")

		if err := core.InjectGadget(appPath, gadgetPath); err != nil {
			fmt.Printf("[!] Injection failed: %v\n", err)
			os.Exit(1)
		}

		// TODO: Repack or proceed to resigning
		fmt.Printf("[+] Injected App located at: %s\n", appPath)
	},
}

func init() {
	rootCmd.AddCommand(injectCmd)
}
