package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Regex patterns for secrets and other info
var (
	urlRegex   = regexp.MustCompile(`(http|https)://[a-zA-Z0-9./?=_-]+`)
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	ipRegex    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// Basic secret patterns
	secretPatterns = map[string]*regexp.Regexp{
		"AWS Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API":  regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		"Stripe Live": regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"Private Key": regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
	}
)

// StaticAnalyze performs static analysis on the extracted app directory using the Target context
func StaticAnalyze(target *Target, externalPatterns map[string]*regexp.Regexp) error {
	fmt.Printf("[*] Starting static analysis on %s...\n", target.AppPath)

	// 1. Get App Info from Plist
	info, err := ParseInfo(filepath.Join(target.AppPath, "Info.plist"))
	if err == nil {
		target.Info = info
		// Populate Report AppInfo
		target.Report.AppInfo.Name = info.CFBundleName
		target.Report.AppInfo.BundleID = info.CFBundleIdentifier
		target.Report.AppInfo.Version = "TODO" // Add logic to get Version string if needed
		target.Report.AppInfo.MinOS = info.MinimumOSVersion
		target.Report.AppInfo.Binary = info.CFBundleExecutable

		fmt.Printf("    App Name: %s\n    Bundle ID: %s\n    Min OS: %s\n", info.CFBundleName, info.CFBundleIdentifier, info.MinimumOSVersion)

		// Check Info.plist misconfigurations
		// ATS
		if info.NSAppTransportSecurity != nil {
			if allows, ok := info.NSAppTransportSecurity["NSAllowsArbitraryLoads"].(bool); ok && allows {
				target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "ATS Disabled (NSAllowsArbitraryLoads = true)")
			}
		}
		// File Sharing
		if info.UIFileSharingEnabled {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "iTunes File Sharing Enabled (UIFileSharingEnabled = true)")
		}
		if info.LSSupportsOpeningDocumentsInPlace {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "Supports Opening Documents in Place (LSSupportsOpeningDocumentsInPlace = true)")
		}
		// URL Schemes
		for _, urlType := range info.CFBundleURLTypes {
			for _, scheme := range urlType.CFBundleURLSchemes {
				target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, fmt.Sprintf("URL Scheme Registered: %s://", scheme))
			}
		}
	}

	// 1.5 Binary Analysis & Entitlements
	// Find the main binary
	if info != nil && info.CFBundleExecutable != "" {
		binaryPath := filepath.Join(target.AppPath, info.CFBundleExecutable)
		target.BinaryPath = binaryPath

		// Binary Security
		if sec, err := CheckBinarySecurity(binaryPath); err == nil {
			target.Report.BinaryAnalysis = sec
		}

		// Entitlements
		if ents, err := DumpEntitlements(binaryPath); err == nil {
			target.Entitlements = ents
			target.Report.Entitlements = ents
			// Check risks
			risks := CheckEntitlements(ents)
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, risks...)
		}
	}

	// 2. Scan binary and other files
	err = filepath.Walk(target.AppPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip signing files and images/assets to save time
		if strings.Contains(path, "_CodeSignature") || strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".car") {
			return nil
		}

		// Read file content
		// Limit size to avoid OOM
		if info.Size() > 10*1024*1024 && !strings.HasSuffix(path, "executable_name_placeholder") {
			// Check if it is the main binary, might be large.
			// Just skip generic large files for regex scanning to be safe for now?
			// Or read first N bytes?
			// Let's stick to full read but be careful.
			// Actually, for binary analysis we used 'strings' command equivalent logic in previous impl?
			// The implementation below uses os.ReadFile.
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		data := string(content)

		// 3. Find URLs
		urlMatches := urlRegex.FindAllString(data, -1)
		for _, u := range urlMatches {
			target.Report.Findings.URLs = append(target.Report.Findings.URLs, u)
		}

		// 4. Find Emails
		emailMatches := emailRegex.FindAllString(data, -1)
		for _, e := range emailMatches {
			target.Report.Findings.Emails = append(target.Report.Findings.Emails, e)
		}

		// 5. Find IPs
		ipMatches := ipRegex.FindAllString(data, -1)
		for _, ip := range ipMatches {
			target.Report.Findings.IPs = append(target.Report.Findings.IPs, ip)
		}

		// Find Secrets
		// 1. Built-in
		for name, pattern := range secretPatterns {
			if matches := pattern.FindAllString(data, -1); matches != nil {
				for _, m := range matches {
					target.Report.Findings.Secrets = append(target.Report.Findings.Secrets, fmt.Sprintf("[%s] %s (in %s)", name, m, filepath.Base(path)))
				}
			}
		}
		// 2. External
		for name, pattern := range externalPatterns {
			if matches := pattern.FindAllString(data, -1); matches != nil {
				for _, m := range matches {
					target.Report.Findings.Secrets = append(target.Report.Findings.Secrets, fmt.Sprintf("[%s] %s (in %s)", name, m, filepath.Base(path)))
				}
			}
		}

		// 7. Obfuscation Detection (Basic) on file content
		if strings.Contains(data, "iXGuard") || strings.Contains(data, "Guardsquare") {
			target.Report.Findings.Obfuscation = append(target.Report.Findings.Obfuscation, "iXGuard/Guardsquare Detected (String Match)")
		}

		return nil
	})

	// Deduplicate findings
	target.Report.Findings.URLs = deduplicate(target.Report.Findings.URLs)
	target.Report.Findings.Emails = deduplicate(target.Report.Findings.Emails)
	target.Report.Findings.IPs = deduplicate(target.Report.Findings.IPs)
	// Secrets might be duplicated if same secret in same file found multiple times?
	// The loop format includes filename, so only extract matches?
	// deduplicate func handles strings.
	target.Report.Findings.Secrets = deduplicate(target.Report.Findings.Secrets)
	target.Report.Findings.Obfuscation = deduplicate(target.Report.Findings.Obfuscation)
	target.Report.Findings.Misconfigurations = deduplicate(target.Report.Findings.Misconfigurations)

	if err != nil {
		return err
	}

	return nil
}

func hasString(content []byte, sub string) bool {
	return strings.Contains(string(content), sub)
}

func deduplicate(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// SecretPattern represents a regex pattern from a template
type SecretPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// LoadPatterns loads regex patterns from a directory of JSON files
func LoadPatterns(rootDir string) (map[string]*regexp.Regexp, error) {
	patterns := make(map[string]*regexp.Regexp)

	// Ensure the rootDir exists, if not, return an empty map and no error
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		return patterns, nil // Directory doesn't exist, no patterns to load
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			content, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("[-] Warning: Could not read pattern file %s: %v\n", path, err)
				return nil // Skip unreadable
			}

			var filePatterns []SecretPattern
			if err := json.Unmarshal(content, &filePatterns); err != nil {
				fmt.Printf("[-] Warning: Could not parse pattern file %s: %v\n", path, err)
				// Try parsing as single object if array fails?
				// The example shown is an array. stick to array for now.
				return nil
			}

			for _, p := range filePatterns {
				// Compile regex
				re, err := regexp.Compile(p.Pattern)
				if err == nil {
					patterns[p.Name] = re
				} else {
					fmt.Printf("[-] Warning: Could not compile regex for pattern '%s' in file %s: %v\n", p.Name, path, err)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return patterns, nil
}
