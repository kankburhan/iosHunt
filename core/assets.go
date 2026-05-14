package core

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed assets/*
var assetsFS embed.FS

// ExtractAsset extracts an embedded asset to a temporary directory and returns the path.
// The caller is responsible for cleaning up the directory if needed, though for short-lived
// scripts, it can be left in os.TempDir().
func ExtractAsset(assetName string) (string, error) {
	content, err := assetsFS.ReadFile("assets/" + assetName)
	if err != nil {
		return "", fmt.Errorf("embedded asset %s not found: %w", assetName, err)
	}

	tempDir := filepath.Join(os.TempDir(), "ioshunt_assets")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp dir for assets: %w", err)
	}

	tempFile := filepath.Join(tempDir, assetName)
	if err := os.WriteFile(tempFile, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write extracted asset to %s: %w", tempFile, err)
	}

	return tempFile, nil
}
