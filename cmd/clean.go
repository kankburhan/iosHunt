package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var cleanAll bool

var cleanCmd = &cobra.Command{
	Use:   "clean <bundle_id>",
	Short: "Remove workspace data for a target",
	Args:  cobra.MaximumNArgs(1),
	Run:   runClean,
}

func init() {
	rootCmd.AddCommand(cleanCmd)
	cleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Remove ALL targets")
}

func runClean(cmd *cobra.Command, args []string) {
	homeDir, _ := os.UserHomeDir()
	baseDir := filepath.Join(homeDir, ".ioshunt", "targets")

	if cleanAll {
		fmt.Printf("[WARNING] You are about to DELETE ALL DATA in %s\n", baseDir)
		if confirm() {
			err := os.RemoveAll(baseDir)
			if err != nil {
				fmt.Printf("[!] Failed to remove all targets: %v\n", err)
			} else {
				fmt.Println("[+] All targets cleaned.")
			}
		}
		return
	}

	if len(args) < 1 {
		fmt.Println("Usage: ioshunt clean <bundle_id> OR ioshunt clean --all")
		return
	}

	bundleID := args[0]
	targetDir := filepath.Join(baseDir, bundleID)

	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("[!] Target not found: %s\n", targetDir)
		return
	}

	fmt.Printf("[*] Removing data for %s...\n", bundleID)
	err := os.RemoveAll(targetDir)
	if err != nil {
		fmt.Printf("[!] Failed to remove target: %v\n", err)
	} else {
		fmt.Println("[+] Target cleaned.")
	}
}

func confirm() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure? (y/N): ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	return strings.ToLower(text) == "y"
}
