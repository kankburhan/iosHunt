package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ioshunt/core"
)

// loadLatestReport finds the most recent report.json for a bundle ID
// inside ~/.ioshunt/targets/<bundle>/<timestamp>/report.json
func loadLatestReport(bundleID string) (*core.Report, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	dir := filepath.Join(homeDir, ".ioshunt", "targets", bundleID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("no scans for %s: %v (run `ioshunt recon %s` first)", bundleID, err, bundleID)
	}
	var latest string
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() {
			continue
		}
		p := filepath.Join(dir, entries[i].Name(), "report.json")
		if _, err := os.Stat(p); err == nil {
			latest = p
			break
		}
	}
	if latest == "" {
		return nil, "", fmt.Errorf("no report.json found in %s", dir)
	}
	data, err := os.ReadFile(latest)
	if err != nil {
		return nil, latest, err
	}
	var r core.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, latest, err
	}
	return &r, latest, nil
}

func saveReport(r *core.Report, path string) error {
	if path == "" {
		return fmt.Errorf("no path")
	}
	return r.SaveJSON(path)
}
