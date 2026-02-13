package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DownloadIPA downloads the IPA for the given bundle ID using ipatool
func DownloadIPA(bundleID, country string) error {
	fmt.Printf("[*] core: Downloading %s (Country: %s)\n", bundleID, country)

	// Construct ipatool command
	args := []string{"download", "-b", bundleID, "--purchase"}
	if country != "" {
		fmt.Printf("[!] Warning: Country override '%s' ignored as ipatool (v2.2+) doesn't support it directly in download.\n", country)
		// args = append(args, "--country", country) // Not supported in v2.2.0
	}

	// We'll rely on ipatool being in the PATH (managed by deps.go)
	cmd := exec.Command("ipatool", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin // Interactive login might be needed

	fmt.Printf("[CMD] ipatool %v\n", args)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ipatool execution failed: %v", err)
	}

	return nil
}

// UnzipIPA extracts the IPA to a destination directory
func UnzipIPA(ipaPath, destDir string) error {
	fmt.Printf("[*] Extracting IPA: %s -> %s\n", ipaPath, destDir)

	// Ensure destDir exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	cmd := exec.Command("unzip", "-o", "-q", ipaPath, "-d", destDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unzip failed: %v", err)
	}

	return nil
}

// FindAppDirectory locates the .app directory inside the extracted Payload
func FindAppDirectory(extractDir string) (string, error) {
	payloadDir := filepath.Join(extractDir, "Payload")
	entries, err := os.ReadDir(payloadDir)
	if err != nil {
		return "", fmt.Errorf("failed to read Payload directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && filepath.Ext(entry.Name()) == ".app" {
			return filepath.Join(payloadDir, entry.Name()), nil
		}
	}

	return "", fmt.Errorf(".app directory not found in Payload")
}
