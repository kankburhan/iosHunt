package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"

	"github.com/spf13/cobra"
)

var (
	identity    string
	useFastlane bool
)

var resignCmd = &cobra.Command{
	Use:   "resign <app-path>",
	Short: "Resign the application",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appPath := args[0]

		var err error
		if useFastlane {
			err = core.ResignAppFastlane(appPath, identity)
		} else {
			err = core.ResignApp(appPath, identity)
		}

		if err != nil {
			fmt.Printf("[!] Resign failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(resignCmd)
	resignCmd.Flags().StringVarP(&identity, "identity", "i", "", "Signing identity (cert name)")
	resignCmd.Flags().BoolVarP(&useFastlane, "fastlane", "f", false, "Use fastlane for resigning")
}
