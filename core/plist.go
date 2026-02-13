package core

import (
	"os"
	"path/filepath"

	"howett.net/plist"
)

// AppInfo contains relevant metadata from Info.plist
type AppInfo struct {
	CFBundleExecutable  string `plist:"CFBundleExecutable"`
	CFBundleIdentifier  string `plist:"CFBundleIdentifier"`
	CFBundleDisplayName string `plist:"CFBundleDisplayName"`
	CFBundleName        string `plist:"CFBundleName"`
	MinimumOSVersion    string `plist:"MinimumOSVersion"`

	// Security / Misconfig check fields
	NSAppTransportSecurity            map[string]interface{} `plist:"NSAppTransportSecurity"`
	UIFileSharingEnabled              bool                   `plist:"UIFileSharingEnabled"`
	LSSupportsOpeningDocumentsInPlace bool                   `plist:"LSSupportsOpeningDocumentsInPlace"`
	CFBundleURLTypes                  []struct {
		CFBundleURLSchemes []string `plist:"CFBundleURLSchemes"`
	} `plist:"CFBundleURLTypes"`
}

// ParseInfo parses the Info.plist file at the given path
func ParseInfo(plistPath string) (*AppInfo, error) {
	f, err := os.Open(plistPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := plist.NewDecoder(f)
	var info AppInfo
	if err := decoder.Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// FindInfo finds Info.plist in the .app directory
func FindInfo(appPath string) (string, error) {
	plistPath := filepath.Join(appPath, "Info.plist")
	if _, err := os.Stat(plistPath); err != nil {
		return "", err
	}
	return plistPath, nil
}
