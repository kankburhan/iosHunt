package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// GHIDRA_SCRIPT default filename in assets
const GHIDRA_SCRIPT = "ghidra_vuln.py"

// GhidraFinding represents a vulnerability found by Ghidra script
type GhidraFinding struct {
	Vulnerability string `json:"vulnerability"`
	Address       string `json:"address"`
	Caller        string `json:"caller"`
	Description   string `json:"description"`
}

// RunGhidraAnalysis executes the headless analyzer on the target binary
func RunGhidraAnalysis(binaryPath, ghidraPath, scriptPath string) ([]GhidraFinding, error) {
	// Locate analyzeHeadless
	// Check common locations
	possiblePaths := []string{
		filepath.Join(ghidraPath, "support", "analyzeHeadless"),
		filepath.Join(ghidraPath, "libexec", "support", "analyzeHeadless"),           // Homebrew
		filepath.Join(ghidraPath, "Contents", "MacOS", "support", "analyzeHeadless"), // macOS App
	}

	var headlessPath string
	for _, p := range possiblePaths {
		pathToCheck := p
		if runtime.GOOS == "windows" {
			pathToCheck += ".bat"
		}
		if _, err := os.Stat(pathToCheck); err == nil {
			headlessPath = pathToCheck
			break
		}
	}

	if headlessPath == "" {
		return nil, fmt.Errorf("analyzeHeadless not found in %s or subdirectories", ghidraPath)
	}

	// Create temp project directory
	tempDir, err := os.MkdirTemp("", "ghidra_scan_")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir) // Clean up project folder

	// Output file
	outputFile := filepath.Join(tempDir, "ghidra_report.json")

	// Construct command
	// analyzeHeadless <project_path> <project_name> -import <binary> -postScript <script_path> <script_args> -deleteProject -noanalysis
	// Note: We need minimal analysis (disassembly + function ID) for xrefs to work.
	// But full auto-analysis is slooow.
	// Let's try default analysis first. If too slow, consider minimal.

	cmd := exec.Command(headlessPath,
		tempDir, "TempProject",
		"-import", binaryPath,
		"-postScript", scriptPath, outputFile,
		"-deleteProject",
		// "-noanalysis", // If enabled, xrefs might be missing
	)

	fmt.Printf("[*] Running Ghidra Headless Analysis... (This may take a while)\n")
	// fmt.Println(cmd.String()) // Debug

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Ghidra analysis failed: %s\nOutput: %s", err, string(output))
	}

	// Read JSON output
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("Ghidra did not produce output file. Check script execution.")
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ghidra report: %w", err)
	}

	var findings []GhidraFinding
	if err := json.Unmarshal(content, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse Ghidra report: %w", err)
	}

	return findings, nil
}
