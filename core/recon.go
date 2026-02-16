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

	// Phase 15 & 17: Expanded Secret Patterns (from internet research/MASVS)
	secretPatterns = map[string]*regexp.Regexp{
		"AWS Key":               regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API":            regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		"Stripe Live":           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"Private Key":           regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		"RSA Private Key":       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		"SSH Private Key":       regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		"Slack Token":           regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
		"Facebook Access Token": regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
		"Twilio API Key":        regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		"Generic API Key":       regexp.MustCompile(`(?i)(api_key|apikey|secret|token).{0,10}['""]([0-9a-zA-Z]{32,45})['""]`),
		"Bearer Token":          regexp.MustCompile(`(?i)Bearer\s[a-zA-Z0-9\-\._~\+\/]+=*`),
		"Hardcoded Password":    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]([^\s'"]{3,})['"]`), // Context-based, imperfect but better than just "password"
	}

	// Phase 15 & 17: Signatures for Vulnerabilities
	hardeningSignatures = map[string]*regexp.Regexp{
		"Insecure Storage (UserDefaults)":           regexp.MustCompile(`UserDefaults`),
		"Insecure Storage (Weak Keychain Always)":   regexp.MustCompile(`kSecAttrAccessibleAlways`),
		"Insecure Storage (Weak Keychain Unlocked)": regexp.MustCompile(`kSecAttrAccessibleWhenUnlocked`),
		"Weak Crypto (MD5)":                         regexp.MustCompile(`CC_MD5`),
		"Weak Crypto (SHA1)":                        regexp.MustCompile(`CC_SHA1`),
		"Weak Crypto (DES)":                         regexp.MustCompile(`kCCAlgorithmDES`),
		"Weak Crypto (ECB)":                         regexp.MustCompile(`kCCOptionECBMode`),
		"Insecure WebView (File Access)":            regexp.MustCompile(`allowUniversalAccessFromFileURLs|allowFileAccessFromFileURLs`),
		"Insecure WebView (JS)":                     regexp.MustCompile(`javaScriptEnabled\s*=\s*(YES|true)|WKScriptMessageHandler`),
		"Network (Weak SSL)":                        regexp.MustCompile(`kSecTrustResultProceed|ssl_session_set_verify`),
		"Network (Plaintext HTTP)":                  regexp.MustCompile(`http://`),
		"Root Detection (Strings)":                  regexp.MustCompile(`/bin/bash|/bin/sh|/usr/sbin/sshd|/usr/bin/ssh|cydia|apt-get|/Applications/Cydia.app`),
		"Logging (NSLog)":                           regexp.MustCompile(`NSLog`),
		"Pasteboard (Usage)":                        regexp.MustCompile(`UIPasteboard`),
		"SQL Injection (Potentially Unsafe API)":    regexp.MustCompile(`sqlite3_exec|executeQuery:|executeUpdate:`),
		"Insecure URL Handling":                     regexp.MustCompile(`UIApplication\.shared\.open`),
		"Code Injection (Eval)":                     regexp.MustCompile(`eval\(`),
		"Potential XSS (WebView)":                   regexp.MustCompile(`loadHTMLString:|evaluateJavaScript:|WKUserScript`),
		"Potential RCE (Process)":                   regexp.MustCompile(`NSTask|\bProcess\b|system\(|popen\(`),
		"XML Injection (XXE)":                       regexp.MustCompile(`shouldResolveExternalEntities:\s*YES`),
		"NSPredicate Injection":                     regexp.MustCompile(`predicateWithFormat:`),
		"Unsafe C Function (Buffer Overflow)":       regexp.MustCompile(`\b(strcpy|strcat|gets|sprintf|vsprintf)\(`),
		"Memory Corruption (Unsafe Copy)":           regexp.MustCompile(`\b(memcpy|memmove)\(`),
	}

	// Manual Heuristics for Cert Pinning
	certPinningMethods = []string{
		"didReceiveChallenge",
		"SecTrustEvaluate",
		"SSLPinned", // Common library terms
		"AFSecurityPolicy",
		"ServerTrustManager", // Alamofire
	}

	// Phase 15: Common Trackers & SDKs
	knownSDKs = []string{
		"GoogleUtilities", "Firebase", "AppsFlyer", "FacebookSDK", "Crashlytics",
		"Alamofire", "AFNetworking", "Adjust", "Mixpanel", "OneSignal", "Kochava",
		"Branch", "Amplitude",
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
		analyzeATS(info, target)

		// Bundle ID
		analyzeBundleID(info, target)

		// File Sharing
		if info.UIFileSharingEnabled {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "iTunes File Sharing Enabled (UIFileSharingEnabled = true)")
		}
		if info.LSSupportsOpeningDocumentsInPlace {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "Supports Opening Documents in Place (LSSupportsOpeningDocumentsInPlace = true)")
		}

		// URL Schemes
		analyzeURLSchemes(info, target)

		// Permissions
		analyzePermissions(info, target)
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

		// Check for Certificate Pinning heuristic in binary
		analyzeCertPinning(binaryPath, target)

		// Entitlements
		if ents, err := DumpEntitlements(binaryPath); err == nil {
			target.Entitlements = ents
			target.Report.Entitlements = ents
			// Check risks
			analyzeEntitlements(ents, target)

			// Phase 23: Deep Links
			analyzeDeepLinks(info, ents, target)
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

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var data string
		if IsBinary(content) {
			// For binaries, we only scan extracted strings
			// This avoids printing raw binary garbage in snippets
			data = ExtractStrings(content)
		} else {
			data = string(content)
		}

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
		scanSecrets(data, path, target, externalPatterns)

		// 7. Obfuscation Detection (Method 1: String Match)
		if strings.Contains(data, "iXGuard") || strings.Contains(data, "Guardsquare") {
			target.Report.Findings.Obfuscation = append(target.Report.Findings.Obfuscation, "iXGuard/Guardsquare Detected (String Match)")
		}

		// 8. Hardening / Signatures
		scanHardeningSignatures(data, path, target)

		// 9. SDK Detection (Simple String Match in binary/files)
		for _, sdk := range knownSDKs {
			if strings.Contains(data, sdk) {
				target.Report.Findings.Trackers = append(target.Report.Findings.Trackers, sdk)
			}
		}

		return nil
	})

	// Deduplicate findings
	target.Report.Findings.URLs = deduplicate(target.Report.Findings.URLs)
	target.Report.Findings.Emails = deduplicate(target.Report.Findings.Emails)
	target.Report.Findings.IPs = deduplicate(target.Report.Findings.IPs)
	target.Report.Findings.Secrets = deduplicateFindings(target.Report.Findings.Secrets)
	target.Report.Findings.Obfuscation = deduplicate(target.Report.Findings.Obfuscation)
	target.Report.Findings.Misconfigurations = deduplicate(target.Report.Findings.Misconfigurations)
	target.Report.Findings.Trackers = deduplicate(target.Report.Findings.Trackers)
	target.Report.Findings.HardeningIssues = deduplicateFindings(target.Report.Findings.HardeningIssues)
	target.Report.Findings.Permissions = deduplicate(target.Report.Findings.Permissions)
	target.Report.Findings.InsecureStorage = deduplicateFindings(target.Report.Findings.InsecureStorage)
	target.Report.Findings.CryptoIssues = deduplicateFindings(target.Report.Findings.CryptoIssues)
	target.Report.Findings.CryptoIssues = deduplicateFindings(target.Report.Findings.CryptoIssues)
	target.Report.Findings.CodeIssues = deduplicateFindings(target.Report.Findings.CodeIssues)
	target.Report.Findings.DeepLinks.Schemes = deduplicate(target.Report.Findings.DeepLinks.Schemes)
	target.Report.Findings.DeepLinks.Universal = deduplicate(target.Report.Findings.DeepLinks.Universal)

	if err != nil {
		return err
	}

	return nil
}

// Helpers

func analyzeATS(info *AppInfo, target *Target) {
	if info.NSAppTransportSecurity != nil {
		if allows, ok := info.NSAppTransportSecurity["NSAllowsArbitraryLoads"].(bool); ok && allows {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "ATS Disabled (NSAllowsArbitraryLoads = true) - Critical Risk")
		}
		if exDomains, ok := info.NSAppTransportSecurity["NSExceptionDomains"].(map[string]interface{}); ok {
			for domain, settings := range exDomains {
				// Check for NSExceptionAllowsInsecureHTTPLoads in domain settings
				if sMap, ok := settings.(map[string]interface{}); ok {
					if insecure, ok := sMap["NSExceptionAllowsInsecureHTTPLoads"].(bool); ok && insecure {
						target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, fmt.Sprintf("ATS Exception: Insecure HTTP allowed for domain %s", domain))
					}
					// Check for NSExceptionRequiresForwardSecrecy = false
					if pfs, ok := sMap["NSExceptionRequiresForwardSecrecy"].(bool); ok && !pfs {
						target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, fmt.Sprintf("ATS Weakness: Forward Secrecy disabled for domain %s", domain))
					}
				}
			}
		}
	}
}

func analyzeBundleID(info *AppInfo, target *Target) {
	lowerID := strings.ToLower(info.CFBundleIdentifier)
	if strings.Contains(lowerID, "debug") || strings.Contains(lowerID, "test") || strings.Contains(lowerID, "stage") {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, fmt.Sprintf("Suspicious Bundle ID (Debug/Test/Stage): %s", info.CFBundleIdentifier))
	}
}

func analyzeCertPinning(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := string(content)

	// Heuristic: If we don't find *any* pinning related terms, flag it as potential missing pinning.
	// But finding them doesn't mean it's secure.
	// Let's frame it as "Pinning Indicators Found" vs "No Pinning Indicators Found".
	foundIndicators := []string{}
	for _, method := range certPinningMethods {
		if strings.Contains(data, method) {
			foundIndicators = append(foundIndicators, method)
		}
	}

	if len(foundIndicators) == 0 {
		target.Report.Findings.HardeningIssues = append(target.Report.Findings.HardeningIssues, Finding{
			Title:       "Missing Certificate Pinning (Heuristic)",
			Description: "No common certificate pinning API calls or libraries found in binary.",
			FilePath:    filepath.Base(binaryPath),
			LineNumber:  0,
			Snippet:     "No signatures found: " + strings.Join(certPinningMethods, ", "),
		})
	} else {
		// Maybe info level finding?
		// for _, ind := range foundIndicators {
		// 	target.Report.Findings.HardeningIssues = append(target.Report.Findings.HardeningIssues, Finding{
		// 		Title:       "Certificate Pinning Indicator",
		// 		Description: "Found potential pinning implementation.",
		// 		FilePath:    filepath.Base(binaryPath),
		// 		LineNumber:  0,
		// 		Snippet:     ind,
		// 	})
		// }
	}
}

func analyzeURLSchemes(info *AppInfo, target *Target) {
	for _, urlType := range info.CFBundleURLTypes {
		for _, scheme := range urlType.CFBundleURLSchemes {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, fmt.Sprintf("URL Scheme Registered: %s://", scheme))
		}
	}
}

func analyzePermissions(info *AppInfo, target *Target) {
	if info.NSCameraUsageDescription != "" {
		target.Report.Findings.Permissions = append(target.Report.Findings.Permissions, "Camera Usage")
	}
	if info.NSMicrophoneUsageDescription != "" {
		target.Report.Findings.Permissions = append(target.Report.Findings.Permissions, "Microphone Usage")
	}
	if info.NSLocationAlwaysUsageDescription != "" {
		target.Report.Findings.Permissions = append(target.Report.Findings.Permissions, "Location Always Usage (High Privacy Risk)")
	}
	if info.NSUserTrackingUsageDescription != "" {
		target.Report.Findings.Permissions = append(target.Report.Findings.Permissions, "User Tracking (IDFA)")
	}
	if info.NSPhotoLibraryUsageDescription != "" {
		target.Report.Findings.Permissions = append(target.Report.Findings.Permissions, "Photo Library Usage")
	}
}

func analyzeDeepLinks(info *AppInfo, ents map[string]interface{}, target *Target) {
	// 1. Custom URL Schemes from Info.plist
	for _, urlType := range info.CFBundleURLTypes {
		for _, scheme := range urlType.CFBundleURLSchemes {
			target.Report.Findings.DeepLinks.Schemes = append(target.Report.Findings.DeepLinks.Schemes, scheme)
		}
	}
	// DeepLinks.Schemes = deduplicate(target.Report.Findings.DeepLinks.Schemes) // Dedup at end

	// 2. Universal Links from Entitlements
	if domains, ok := ents["com.apple.developer.associated-domains"]; ok {
		// Can be []interface{} or []string
		if list, ok := domains.([]interface{}); ok {
			for _, d := range list {
				if s, ok := d.(string); ok {
					target.Report.Findings.DeepLinks.Universal = append(target.Report.Findings.DeepLinks.Universal, s)
				}
			}
		}
	}
}

func analyzeEntitlements(ents map[string]interface{}, target *Target) {
	if val, ok := ents["get-task-allow"].(bool); ok && val {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "get-task-allow is TRUE (App is debuggable/development build)")
	}
	if _, ok := ents["security.application-groups"]; ok {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "App Groups Enabled (Potential IPC Risk)")
	}
	if _, ok := ents["keychain-access-groups"]; ok {
		// Just noting it
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations, "Keychain Access Groups Used")
	}
	if _, ok := ents["com.apple.security.app-sandbox"]; !ok {
		// Usually present, but if missing on iOS?
	}
}

func scanSecrets(data, path string, target *Target, externalPatterns map[string]*regexp.Regexp) {
	lines := strings.Split(data, "\n")

	// Helper to process patterns
	processPatterns := func(patterns map[string]*regexp.Regexp) {
		for name, pattern := range patterns {
			matches := pattern.FindAllStringSubmatchIndex(data, -1)
			for _, m := range matches {
				start := m[0]

				// Determine Value: Default to full match, or use the last capture group if available
				valStart, valEnd := m[0], m[1]
				if len(m) > 2 {
					valStart, valEnd = m[len(m)-2], m[len(m)-1]
				}
				// Verify bounds
				if valStart < 0 || valEnd > len(data) || valStart >= valEnd {
					valStart, valEnd = m[0], m[1] // Fallback
				}
				value := data[valStart:valEnd]

				lineNo, snippet := extractContext(lines, start, data)

				target.Report.Findings.Secrets = append(target.Report.Findings.Secrets, Finding{
					Title:       name,
					Description: fmt.Sprintf("Found %s secret", name),
					FilePath:    filepath.Base(path),
					LineNumber:  lineNo,
					Snippet:     snippet,
					Value:       value,
				})

				// Limit secrets per file to avoid flooding
				if len(target.Report.Findings.Secrets) > 1000 {
					return
				}
			}
		}
	}

	// Builts-in
	processPatterns(secretPatterns)
	// External
	processPatterns(externalPatterns)
}

func scanHardeningSignatures(data, path string, target *Target) {
	lines := strings.Split(data, "\n")

	for name, pattern := range hardeningSignatures {
		matches := pattern.FindAllStringIndex(data, -1)
		for _, m := range matches {
			start := m[0]

			lineNo, snippet := extractContext(lines, start, data)

			finding := Finding{
				Title:      name,
				FilePath:   filepath.Base(path),
				LineNumber: lineNo,
				Snippet:    snippet,
			}

			if strings.Contains(name, "Insecure Storage") {
				target.Report.Findings.InsecureStorage = append(target.Report.Findings.InsecureStorage, finding)
			} else if strings.Contains(name, "Weak Crypto") {
				target.Report.Findings.CryptoIssues = append(target.Report.Findings.CryptoIssues, finding)
			} else if strings.Contains(name, "SQL Injection") || strings.Contains(name, "Code Injection") || strings.Contains(name, "Potential XSS") || strings.Contains(name, "Potential RCE") || strings.Contains(name, "XML Injection") || strings.Contains(name, "NSPredicate") || strings.Contains(name, "Unsafe C") || strings.Contains(name, "Memory Corruption") {
				target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, finding)
			} else {
				target.Report.Findings.HardeningIssues = append(target.Report.Findings.HardeningIssues, finding)
			}
		}
	}
}

// extractContext finds the line number and a snippet of code around the match
// This implementation is a bit inefficient (re-calculating string offsets to lines),
// but functional for typical app sizes.
// Optimization: Pass cumulative length?
// Or simply:
// 1. Locate the match in 'data'.
// 2. Count newlines before match to get LineNumber.
// 3. Find the specific line string for Snippet.
func extractContext(lines []string, start int, fullData string) (int, string) {
	// Count newlines before 'start'
	prefix := fullData[:start]
	lineNo := strings.Count(prefix, "\n") + 1

	if lineNo > 0 && lineNo <= len(lines) {
		snippet := strings.TrimSpace(lines[lineNo-1])
		if len(snippet) > 100 {
			snippet = snippet[:100] + "..."
		}
		return lineNo, snippet
	}

	return lineNo, ""
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

func deduplicateFindings(slice []Finding) []Finding {
	keys := make(map[string]bool)
	list := []Finding{}
	for _, entry := range slice {
		// Unique key: Title + File + Line
		key := fmt.Sprintf("%s|%s|%d", entry.Title, entry.FilePath, entry.LineNumber)
		if _, value := keys[key]; !value {
			keys[key] = true
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

// IsBinary checks if the content appears to be binary
func IsBinary(content []byte) bool {
	// Check first 1024 bytes for null character
	// A common simple heuristic
	limit := 1024
	if len(content) < limit {
		limit = len(content)
	}
	for i := 0; i < limit; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// ExtractStrings extracts printable strings from binary content (min length 4)
func ExtractStrings(content []byte) string {
	var sb strings.Builder
	var cur []byte

	// Printable chars: 32-126, plus tab/newline?
	isPrintable := func(b byte) bool {
		return (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13
	}

	for _, b := range content {
		if isPrintable(b) {
			cur = append(cur, b)
		} else {
			if len(cur) >= 4 {
				sb.Write(cur)
				sb.WriteByte('\n')
			}
			cur = cur[:0]
		}
	}
	// Flush last
	if len(cur) >= 4 {
		sb.Write(cur)
		sb.WriteByte('\n')
	}

	return sb.String()
}
