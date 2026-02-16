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

// CheckEntitlements -> redundant, logic moved to recon.go analyzeEntitlements
