package core

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Target represents the current assessment target and context
type Target struct {
	BundleID   string
	IPAPath    string
	AppPath    string // Path to the extracted .app directory
	BinaryPath string // Path to the main executable binary

	// Metadata
	Info         *AppInfo
	Entitlements map[string]interface{}

	// Workspace
	WorkDir string // ~/.ioshunt/targets/<bundle_id>/<timestamp>

	// Findings & Report
	Report *Report
}

// NewTarget initializes a new target context and workspace
func NewTarget(bundleID string) (*Target, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %v", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	workDir := filepath.Join(homeDir, ".ioshunt", "targets", bundleID, timestamp)

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %v", err)
	}

	return &Target{
		BundleID: bundleID,
		WorkDir:  workDir,
		Report:   NewReport(bundleID),
	}, nil
}
