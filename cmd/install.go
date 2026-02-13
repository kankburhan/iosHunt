package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"

	"github.com/spf13/cobra"
)

var deviceID string

var installCmd = &cobra.Command{
	Use:   "install <app-path>",
	Short: "Install the application to a connected device",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appPath := args[0]

		err := core.InstallApp(appPath, deviceID)
		if err != nil {
			fmt.Printf("[!] Install failed: %v\n", err)
			os.Exit(1)
		}

		// Optional: Launch?
		// core.LaunchApp(appPath, deviceID)
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().StringVarP(&deviceID, "device", "d", "", "Device ID (UDID)")
}
