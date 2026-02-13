package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:     "auth",
	Aliases: []string{"login"},
	Short:   "Authenticate with App Store (via ipatool)",
	Long: `Authenticates with Apple ID to enable IPA downloads.
This command wraps 'ipatool auth login' and is interactive.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Starting authentication flow...")

		// Determine ipatool path
		ipaPath, err := exec.LookPath("ipatool")
		if err != nil {
			// Fallback to local bin if not in path (though deps check should have added it)
			home, _ := os.UserHomeDir()
			ipaPath = home + "/.ioshunt/bin/ipatool"
		}

		c := exec.Command(ipaPath, "auth", "login")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Stdin = os.Stdin

		if err := c.Run(); err != nil {
			fmt.Printf("[!] Authentication failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] Authentication successful.")
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
}
