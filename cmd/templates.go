package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "Manage custom regex templates",
	Long:  `Manage external regex templates for secret scanning from https://github.com/kankburhan/gosek-templates`,
}

var templatesUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download or update templates from GitHub",
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, _ := os.UserHomeDir()
		templatesDir := filepath.Join(homeDir, ".ioshunt", "templates")
		repoURL := "https://github.com/kankburhan/gosek-templates"

		if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
			// Clone
			fmt.Printf("[*] Cloning templates from %s...\n", repoURL)
			if err := runGit("clone", repoURL, templatesDir); err != nil {
				fmt.Printf("[!] Failed to clone templates: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Templates downloaded successfully.")
		} else {
			// Pull
			fmt.Println("[*] Updating templates...")
			if err := runGitCwd(templatesDir, "pull"); err != nil {
				fmt.Printf("[!] Failed to update templates: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Templates updated successfully.")
		}
	},
}

func runGit(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runGitCwd(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func init() {
	rootCmd.AddCommand(templatesCmd)
	templatesCmd.AddCommand(templatesUpdateCmd)
}
