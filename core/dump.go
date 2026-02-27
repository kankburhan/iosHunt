package core

import (
	"fmt"
)

// DumpType defines the type of data to dump
type DumpType string

const (
	DumpKeychain DumpType = "keychain"
	DumpDefaults DumpType = "defaults"
	DumpCookies  DumpType = "cookies"
	DumpAppInfo  DumpType = "app_info"
)

// DumpData attaches to the app and runs the specific dump script
func DumpData(bundleID string, dumpType DumpType) error {
	var scriptName string
	switch dumpType {
	case DumpKeychain:
		scriptName = "keychain_dump.js"
	case DumpDefaults:
		scriptName = "defaults_dump.js"
	case DumpCookies:
		scriptName = "cookies_dump.js"
	case DumpAppInfo:
		scriptName = "app_info.js"
	default:
		return fmt.Errorf("unsupported dump type: %s", dumpType)
	}

	scriptPath, err := GetAssetScript(scriptName)
	if err != nil {
		return fmt.Errorf("failed to locate script %s: %v", scriptName, err)
	}

	fmt.Printf("[*] Launching dump for %s (%s)...\n", bundleID, dumpType)
	fmt.Println("[*] Please interact with the app on the device to trigger keychain access if needed.")

	// We use AttachToApp in interactive mode so user can see output or interact
	return AttachToApp(bundleID, scriptPath)
}
