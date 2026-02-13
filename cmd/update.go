package cmd

import (
	"fmt"
	"ioshunt/core"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ioshunt to the latest version",
	Run:   runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) {
	fmt.Println("[*] Checking for updates...")

	// For a dev tool distributed via source/git often, "git pull && go install" is the best way.
	// If it was a binary distribution, we'd download the binary.
	// Let's assume git based update for now as per plan.

	// Check if .git exists
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Println("[!] Not a git repository. Cannot auto-update via git.")
		fmt.Printf("[*] Please visit https://github.com/%s/%s/releases to download the latest binary.\n", core.RepoOwner, core.RepoName)
		return
	}

	fmt.Println("[*] Pulling latest changes...")
	gitPull := exec.Command("git", "pull")
	gitPull.Stdout = os.Stdout
	gitPull.Stderr = os.Stderr
	if err := gitPull.Run(); err != nil {
		fmt.Printf("[!] Update failed (git pull): %v\n", err)
		return
	}

	fmt.Println("[*] Rebuilding and installing...")
	goInstall := exec.Command("go", "install")
	goInstall.Stdout = os.Stdout
	goInstall.Stderr = os.Stderr
	if err := goInstall.Run(); err != nil {
		fmt.Printf("[!] Update failed (go install): %v\n", err)
		return
	}

	fmt.Println("[+] Update complete! run 'ioshunt version' to verify.")
}
