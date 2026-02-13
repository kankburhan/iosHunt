package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check if all dependencies are installed",
	Run:   runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) {
	fmt.Println("[*] Checking iOSHunt Environment...")

	// 1. Check Directory
	home, err := os.UserHomeDir()
	if err != nil {
		printStatus("Home Directory", false, err.Error())
	} else {
		workDir := filepath.Join(home, ".ioshunt")
		if _, err := os.Stat(workDir); os.IsNotExist(err) {
			printStatus("Workspace (~/.ioshunt)", false, "Not Found")
		} else {
			printStatus("Workspace (~/.ioshunt)", true, workDir)
		}
	}

	// 2. Check Dependencies
	dependencies := []string{
		"frida",
		"objection",
		"sshpass",
		"ideviceinstaller",
		"unzip",
		"codesign",
		"security",
	}

	for _, dep := range dependencies {
		path, err := exec.LookPath(dep)
		if err == nil {
			printStatus(dep, true, path)
		} else {
			printStatus(dep, false, "Not Installed (Required)")
		}
	}

	// 3. Optional
	optional := []string{
		"code",     // VS Code
		"open",     // macOS open
		"fastlane", // Fastlane tools
	}

	for _, dep := range optional {
		path, err := exec.LookPath(dep)
		if err == nil {
			printStatus(dep, true, path)
		} else {
			printStatus(dep, true, "Not Installed (Optional)") // True because it's optional
		}
	}
}

func printStatus(name string, success bool, details string) {
	if success {
		if details == "Not Installed (Optional)" {
			// Yellowish for optional missing?
			fmt.Printf(" [?] %-20s: %s\n", name, details)
		} else {
			fmt.Printf(" [OK] %-20s: %s\n", name, details)
		}
	} else {
		fmt.Printf(" [!!] %-20s: %s\n", name, details)
	}
}
