package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"

	"github.com/spf13/cobra"
)

var (
	countryCode  string
	skipDownload bool
)

var downloadCmd = &cobra.Command{
	Use:   "download <bundle-id>",
	Short: "Download IPA from App Store",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bundleID := args[0]

		if skipDownload {
			fmt.Println("[*] Skipping download as requested.")
			return
		}

		fmt.Printf("[*] Downloading IPA for %s...\n", bundleID)

		// Initialize Core IPA handler
		// ipaHandler := core.NewIPAHandler()
		// err := ipaHandler.Download(bundleID, countryCode)

		// For now, placeholders
		// We'll call ipatool directly here or via core

		err := core.DownloadIPA(bundleID, countryCode)
		if err != nil {
			fmt.Printf("[!] Download failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] IPA downloaded successfully.")
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadCmd.Flags().StringVar(&countryCode, "country", "US", "App Store country code")
	downloadCmd.Flags().BoolVar(&skipDownload, "skip-download", false, "Skip downloading IPA")
}
