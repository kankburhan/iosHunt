package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// AttachToApp attaches Frida to the running app with the given script(s)
func AttachToApp(bundleIDOrName string, scriptPaths ...string) error {
	fmt.Printf("[*] Attaching Frida to %s...\n", bundleIDOrName)

	args := []string{"-U", "-n", bundleIDOrName} // -n for name/gadget, -U for USB
	// Note: If using Gadget, usually it waits or connects.
	// If the app is identifying as "Gadget", use "Gadget" or the bundle name.
	// If we injected the gadget, the process name might be the binary name.

	for _, p := range scriptPaths {
		if p != "" {
			args = append(args, "-l", p)
		}
	}

	// Interactive mode
	// We want the user to interact with the Frida REPL
	cmd := exec.Command("frida", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		// Try fallback to -F (frontmost) if specific name fails
		fmt.Println("[!] Failed to attach by name. Trying frontmost application...")
		cmd = exec.Command("frida", "-U", "-F")
		for _, p := range scriptPaths {
			if p != "" {
				cmd.Args = append(cmd.Args, "-l", p)
			}
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("frida attach failed: %v", err)
		}
	}

	return nil
}

// GetAssetScript returns the path to the internal script
func GetAssetScript(scriptName string) (string, error) {
	// For development, we look in assets/ relative to pwd.
	// For production/binary, we might need embedded assets.
	// Assuming pwd for now.

	cwd, _ := os.Getwd()
	path := filepath.Join(cwd, "assets", scriptName)
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

// GetPluginScript returns the path to a plugin script
func GetPluginScript(pluginName string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Ensure name ends with .js
	if filepath.Ext(pluginName) != ".js" {
		pluginName += ".js"
	}

	path := filepath.Join(homeDir, ".ioshunt", "plugins", pluginName)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("plugin not found: %s", path)
	}
	return path, nil
}
