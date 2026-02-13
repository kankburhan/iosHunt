package core

import (
	"bytes"
	"fmt"
	"os/exec"

	"howett.net/plist"
)

// DumpEntitlements extracts entitlements from a binary
func DumpEntitlements(binaryPath string) (map[string]interface{}, error) {
	cmd := exec.Command("codesign", "-d", "--entitlements", ":-", binaryPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	// codesign writes to stderr sometimes? No, standard output for -
	// But let's capture stderr too just in case
	var errOut bytes.Buffer
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("codesign failed: %v | stderr: %s", err, errOut.String())
	}

	// Parse Plist from output
	// The output is XML plist
	var entitlements map[string]interface{}
	if _, err := plist.Unmarshal(out.Bytes(), &entitlements); err != nil {
		return nil, fmt.Errorf("failed to parse entitlements plist: %v", err)
	}

	return entitlements, nil
}

// CheckEntitlements analyzes entitlements for risks
func CheckEntitlements(entitlements map[string]interface{}) []string {
	var findings []string

	// Check 1: Debuggable
	if val, ok := entitlements["get-task-allow"]; ok {
		if boolVal, ok := val.(bool); ok && boolVal {
			findings = append(findings, "get-task-allow: true (App is debuggable - Critical for Production)")
		}
	}

	// Check 2: Sandbox
	if _, ok := entitlements["com.apple.security.app-sandbox"]; !ok {
		// Does unrelated to iOS? iOS apps are always sandboxed?
		// Usually provisioning profile dictates this.
		// findings = append(findings, "com.apple.security.app-sandbox: missing")
		// Actually typical iOS app entitlements might not explicitly list it if it's default?
		// Let's stick to known risky ones.
	}

	// Check 3: APS Environment
	if val, ok := entitlements["aps-environment"]; ok {
		findings = append(findings, fmt.Sprintf("Push Notifications (aps-environment): %v", val))
	}

	return findings
}
