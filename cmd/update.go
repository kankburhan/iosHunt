package cmd

import (
	"fmt"
	"github.com/kankburhan/iosHunt/core"
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
	fmt.Printf("[*] Current version : %s\n", core.CurrentVersion)
	fmt.Println("[*] Checking for updates...")

	// Prefer go install @latest (works whether installed from source or via go install)
	if goPath, err := exec.LookPath("go"); err == nil {
		fmt.Println("[*] Updating via go install...")
		pkg := core.GoInstallPath + "@latest"
		goInstall := exec.Command(goPath, "install", pkg)
		goInstall.Stdout = os.Stdout
		goInstall.Stderr = os.Stderr
		if err := goInstall.Run(); err != nil {
			fmt.Printf("[!] go install failed: %v\n", err)
			fmt.Printf("[*] Manual install: go install %s\n", pkg)
			fallbackGitUpdate()
			return
		}
		fmt.Printf("[+] Updated successfully! Run 'ioshunt version' to confirm.\n")
		return
	}

	// Fallback: git pull + go install (dev/cloned repo)
	fallbackGitUpdate()
}

func fallbackGitUpdate() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("[!] Cannot auto-update: 'go' not found and not a git repo.\n")
		fmt.Printf("[*] Visit https://github.com/%s/%s/releases\n", core.RepoOwner, core.RepoName)
		return
	}

	fmt.Println("[*] Falling back to git pull + go install...")
	gitPull := exec.Command("git", "pull")
	gitPull.Stdout = os.Stdout
	gitPull.Stderr = os.Stderr
	if err := gitPull.Run(); err != nil {
		fmt.Printf("[!] git pull failed: %v\n", err)
		return
	}

	goInstall := exec.Command("go", "install")
	goInstall.Stdout = os.Stdout
	goInstall.Stderr = os.Stderr
	if err := goInstall.Run(); err != nil {
		fmt.Printf("[!] go install failed: %v\n", err)
		return
	}
	fmt.Println("[+] Updated successfully! Run 'ioshunt version' to confirm.")
}
