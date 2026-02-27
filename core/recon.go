package core

import (
	"encoding/json"
	"fmt"
	"math"
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
		"Insecure Deserialization (NSCoding)":       regexp.MustCompile(`initWithCoder:|encodeWithCoder:|conform.*NSCoding|NSSecureCoding`),
		"Unsafe Custom URL Scheme (No Validation)":  regexp.MustCompile(`openURL:|application.*open.*URL|handleOpenURL`),
		"Keychain Sharing Vulnerability":            regexp.MustCompile(`kSecAttrAccessGroup|kSecClass.*kSecAttrAccessGroup`),
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

	// Known 3rd-party library binary names to skip for vulnerability findings
	// These produce massive noise (ObjC symbols, class metadata) that drowns real findings
	knownThirdPartyLibs = []string{
		"FirebaseCore", "FirebaseCoreInternal", "FirebaseInstallations",
		"FirebaseMessaging", "FirebaseAnalytics", "FirebaseCrashlytics",
		"GoogleUtilities", "GoogleSignIn", "GTMSessionFetcher", "GoogleDataTransport",
		"OneSignalCore", "OneSignalExtension", "OneSignalFramework",
		"OneSignalInAppMessages", "OneSignalLiveActivities",
		"OneSignalNotifications", "OneSignalOSCore", "OneSignalOutcomes",
		"OneSignalUser",
		"AppAuth", "SDWebImage", "Sentry",
		"Alamofire", "AFNetworking",
		"Capacitor", "CapacitorApp", "CapacitorAppLauncher",
		"CapacitorBlobWriter", "CapacitorBrowser", "CapacitorCamera",
		"CapacitorClipboard", "CapacitorCommunityAppleSignIn",
		"CapacitorKeyboard", "CapacitorFilesystem", "CapacitorPreferences",
		"CapacitorHaptics", "CapacitorStatusBar", "CapacitorSplashScreen",
		"GCDWebServer", "Cordova", "CordovaPlugins",
		"FBSDKCoreKit", "FBSDKLoginKit", "FBSDKShareKit",
		"Bolts", "nanopb", "PromisesObjC",
	}

	// ObjC symbol prefixes that are class metadata, not actual secrets
	objcSymbolPrefixes = []string{
		"_OBJC_CLASS_$_",
		"_OBJC_METACLASS_$_",
		"_OBJC_IVAR_$_",
		"_objc_msgSend$",
		"__OBJC_$_",
		"__OBJC_METACLASS_RO_$_",
		"__OBJC_CLASS_RO_$_",
		"__OBJC_$_INSTANCE_METHODS_",
		"__OBJC_$_CLASS_METHODS_",
		"__OBJC_$_INSTANCE_VARIABLES_",
		"__OBJC_$_PROP_LIST_",
		"_OBJC_CLASSLIST_",
		"__METACLASS_DATA_",
		"__DATA__Tt",
		"_symbolic ",
	}

	// Hardening false positive patterns — Apple system content that always appears
	hardeningFalsePositives = []string{
		"apple.com/DTDs/PropertyList",
		"ocsp.apple.com",
		"crl.apple.com",
		"apple.com/appleca",
		"apple.com/certificateauthority",
		"w3.org",
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

			// NEW FEATURE 2: Keychain Sharing Analysis
			AnalyzeKeychainSharingRisks(ents, target)

			// NEW FEATURE 5: App Extension Security
			AnalyzeAppExtensionSecurity(ents, target)

			// BUG BOUNTY FEATURE 4: Entitlements misconfiguration
			AnalyzeEntitlementsMisconfig(ents, target)

			// BUG BOUNTY FEATURE 5: Network security configuration
			AnalyzeNetworkSecurityConfig(info, ents, target)
		}

		// NEW FEATURE 1: NSCoding Security Analysis
		AnalyzeNSCodingSecurity(binaryPath, target)

		// NEW FEATURE 3: URL Scheme Validation Analysis
		if info != nil {
			AnalyzeURLSchemeValidation(info, binaryPath, target)
		}

		// NEW FEATURE 4: Background Activity Leak Detection
		DetectBackgroundActivityLeaks(binaryPath, target)

		// BUG BOUNTY FEATURES (5 new detectors based on real-world iOS vulnerability research)
		// Feature 1: Keychain API misuse
		AnalyzeKeychainAPIUsage(binaryPath, target)

		// Feature 2: Hardcoded secrets with entropy analysis
		AnalyzeHardcodedSecrets(binaryPath, target)

		// Feature 3: Logging data leaks (credentials in log statements)
		AnalyzeLoggingStatements(binaryPath, target)
	}

	// 2. Scan binary and other files

	err = filepath.Walk(target.AppPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip signing files, images, assets, and SVG files to save time
		if strings.Contains(path, "_CodeSignature") || strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".car") || strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg") || strings.HasSuffix(path, ".gif") || strings.HasSuffix(path, ".webp") || strings.HasSuffix(path, ".ttf") || strings.HasSuffix(path, ".otf") || strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2") {
			return nil
		}

		// Check if this file is from a known 3rd-party library
		baseName := filepath.Base(path)
		isThirdParty := isThirdPartyFile(baseName)

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

		// 3. Find URLs (always scan all files for URLs)
		urlMatches := urlRegex.FindAllString(data, -1)
		for _, u := range urlMatches {
			target.Report.Findings.URLs = append(target.Report.Findings.URLs, u)
		}

		// Skip deeper analysis for 3rd-party library files
		if isThirdParty {
			return nil
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
	target.Report.Findings.URLs = filterFalsePositiveURLs(target.Report.Findings.URLs)
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

				// Skip ObjC metadata symbols — these are class/method names, not actual secrets
				if isObjCSymbol(snippet) || isObjCSymbol(value) {
					continue
				}

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
	baseName := filepath.Base(path)

	// IMPROVED: Skip SDK code to reduce false positives
	sdk_patterns := []string{"FBSDK", "CleverTap", "MoEngage", "OneSignal", "Firebase",
		"GoogleAnalytics", "Amplitude", "Sentry", "Adjust", "AppsFlyer", "Mixpanel",
		"Capabilities", "Branch", "Kochava", "TwitterKit"}
	for _, sdk := range sdk_patterns {
		if strings.Contains(baseName, sdk) {
			return // Skip entire SDK file
		}
	}

	for name, pattern := range hardeningSignatures {
		matches := pattern.FindAllStringIndex(data, -1)
		for _, m := range matches {
			start := m[0]

			lineNo, snippet := extractContext(lines, start, data)

			// Skip hardening false positives
			if isHardeningFalsePositive(name, snippet) {
				continue
			}

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
			} else if strings.Contains(name, "SQL Injection") || strings.Contains(name, "Code Injection") || strings.Contains(name, "Potential XSS") || strings.Contains(name, "Potential RCE") || strings.Contains(name, "XML Injection") || strings.Contains(name, "NSPredicate") || strings.Contains(name, "Unsafe C") || strings.Contains(name, "Memory Corruption") || strings.Contains(name, "Unsafe Custom URL") || strings.Contains(name, "Unvalidated URL") {
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

// filterFalsePositiveURLs removes known false positive URLs from results
// These are standard Apple/W3C URLs that appear in every iOS app and are not interesting
func filterFalsePositiveURLs(urls []string) []string {
	filtered := []string{}
	for _, u := range urls {
		lower := strings.ToLower(u)
		// Skip w3.org URLs
		if strings.Contains(lower, "www.w3.org") || strings.Contains(lower, "w3.org") {
			continue
		}
		// Skip *.apple.com URLs
		if strings.Contains(lower, "apple.com") {
			continue
		}
		filtered = append(filtered, u)
	}
	return filtered
}

// isThirdPartyFile checks if a filename matches a known 3rd-party library
func isThirdPartyFile(filename string) bool {
	for _, lib := range knownThirdPartyLibs {
		if filename == lib || strings.HasPrefix(filename, lib+".") || strings.HasPrefix(filename, lib+"_") {
			return true
		}
	}
	// Also skip PrivacyInfo.xcprivacy files (Apple privacy manifests)
	if filename == "PrivacyInfo.xcprivacy" {
		return true
	}
	return false
}

// isObjCSymbol checks if a snippet is an Objective-C metadata symbol (not a real secret)
func isObjCSymbol(s string) bool {
	trimmed := strings.TrimSpace(s)
	for _, prefix := range objcSymbolPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	// Also skip Swift mangled symbols
	if strings.HasPrefix(trimmed, "_$s") || strings.HasPrefix(trimmed, "_$S") {
		return true
	}
	return false
}

// isHardeningFalsePositive checks if a hardening finding is a known false positive
func isHardeningFalsePositive(name, snippet string) bool {
	lower := strings.ToLower(snippet)

	// Plaintext HTTP: skip Apple system URLs
	if name == "Network (Plaintext HTTP)" {
		for _, fp := range hardeningFalsePositives {
			if strings.Contains(lower, strings.ToLower(fp)) {
				return true
			}
		}
	}

	// RCE: skip JS files that just contain the word "Process" in comments/strings
	if name == "Potential RCE (Process)" {
		// If the snippet is just a comment or regular word usage, skip
		if !strings.Contains(snippet, "NSTask") &&
			!strings.Contains(snippet, "system(") &&
			!strings.Contains(snippet, "popen(") {
			// It's likely just the word "Process" in a JS string/comment
			return true
		}
	}

	// Code Injection: skip minified JS eval() in non-suspicious contexts
	if name == "Code Injection (Eval)" {
		if strings.HasSuffix(strings.ToLower(filepath.Base(snippet)), ".js") {
			// JS files commonly use eval-like patterns in bundlers
			return true
		}
	}

	return false
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

// ============================================
// NEW FEATURE 1: Insecure Deserialization Analysis
// ============================================

// AnalyzeNSCodingSecurity checks for unsafe NSCoding implementations
func AnalyzeNSCodingSecurity(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := string(content)
	baseName := filepath.Base(binaryPath)

	// Skip SDK code to prevent false positives
	sdk_patterns := []string{"FBSDK", "CleverTap", "MoEngage", "OneSignal", "Firebase",
		"GoogleAnalytics", "Amplitude", "Sentry", "Adjust", "AppsFlyer"}
	for _, sdk := range sdk_patterns {
		if strings.Contains(baseName, sdk) {
			return
		}
	}

	// IMPROVED: Pattern 1 - initWithCoder without NSSecureCoding WITH POC
	if strings.Contains(data, "initWithCoder") && !strings.Contains(data, "NSSecureCoding") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "Unsafe NSCoding (Possible Object Injection - CRITICAL)",
			Description: "CRITICAL: class implements NSCoding WITHOUT NSSecureCoding. EXPLOITATION: Create malicious plist with arbitrary object. User opens file → app calls unarchiveObject() → object init executes attacker code. POC: Build object with code in initWithCoder: that calls system() or launches malware. IMPACT: Remote Code Execution, device compromise.",
			FilePath:    filepath.Base(binaryPath),
			LineNumber:  0,
			Snippet:     "POC: Malicious plist → [NSKeyedUnarchiver unarchiveObjectWithData:data] → initWithCoder: executes = RCE",
		})
	}

	// IMPROVED: Pattern 2 - NSKeyedUnarchiver without allowedClasses WITH POC
	if strings.Contains(data, "NSKeyedUnarchiver") && !strings.Contains(data, "allowedClasses") &&
		!strings.Contains(data, "NSSecureCoding") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "Unsafe NSKeyedUnarchiver Usage (Object Injection - CRITICAL)",
			Description: "CRITICAL: NSKeyedUnarchiver.unarchiveObject() WITHOUT allowedClasses. EXPLOITATION: Deserializes ANY object type. Attacker creates CustomObject with malicious code → app deserializes → code executes. NO validation means attacker has full control over object type. IMPACT: Arbitrary code execution, data theft, malware installation.",
			FilePath:    filepath.Base(binaryPath),
			LineNumber:  0,
			Snippet:     "POC: [NSKeyedUnarchiver unarchiveObjectWithData:maliciousPlist] → Deserializes attacker's object → -[AttackerObject initWithCoder:] → system(@\"malware_command\")",
		})
	}

	// IMPROVED: Pattern 3 - Legacy unarchiveObjectWithData WITH POC
	if strings.Contains(data, "unarchiveObjectWithData") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "Deprecated Deserialization API (CRITICAL - Unsafe)",
			Description: "CRITICAL: Uses deprecated unarchiveObjectWithData - KNOWN UNSAFE. EXPLOITATION: This exact API is exploited by object injection attacks. Apple explicitly says: DO NOT USE. FIXED BY: Use unarchiveTopLevelObjectWithData:allowingSecureCoding:error: with restricted class list. IMPACT: Direct RCE vector.",
			FilePath:    filepath.Base(binaryPath),
			LineNumber:  0,
			Snippet:     "POC: -[NSKeyedUnarchiver unarchiveObjectWithData:] is the EXACT vector for object injection RCE",
		})
	}
}

// ============================================
// NEW FEATURE 2: Keychain Sharing Attack Surface Analysis
// ============================================

// AnalyzeKeychainSharingRisks checks for overpermissive keychain access groups
func AnalyzeKeychainSharingRisks(ents map[string]interface{}, target *Target) {
	if accessGroups, ok := ents["keychain-access-groups"]; ok {
		// Check if keychain-access-groups too permissive
		if groupList, ok := accessGroups.([]interface{}); ok {
			for _, g := range groupList {
				groupStr := fmt.Sprintf("%v", g)

				// Skip framework-level groups (false positive prevention)
				skipFrameworkGroups := []string{"com.apple.", "$(AppIdentifierPrefix)"}
				shouldSkip := false
				for _, skip := range skipFrameworkGroups {
					if strings.HasPrefix(groupStr, skip) {
						shouldSkip = true
						break
					}
				}
				if shouldSkip {
					continue
				}

				// IMPROVED: Risk 1 - Sharing with app groups WITH POC
				if strings.Contains(groupStr, "group.") {
					target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
						fmt.Sprintf("VULNERABILITY: Keychain Shared via App Groups: %s\nEXPLOITATION: Create attacker app with same app group ID. Attacker app can read/write all keychain items. POC: SecItemCopyMatching(queryForGroup) returns all tokens, passwords.\nIMPACT: Auth token theft, account takeover, cross-app data theft", groupStr))
				}

				// IMPROVED: Risk 2 - Wildcard sharing CRITICAL!
				if strings.Contains(groupStr, "*") {
					target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
						fmt.Sprintf("CRITICAL: Keychain shared with WILDCARD: %s\nEXPLOITATION: ANY app on device can access keychain. Attacker app reads all stored secrets, tokens, passwords. POC: Simple query to keychain with group ID = attacker gets everything.\nIMPACT: MAXIMUM RISK - Complete compromise of stored secrets", groupStr))
				}

				// IMPROVED: Risk 3 - Team ID sharing WITH POC
				if strings.HasPrefix(groupStr, "TEAMID.") || strings.Contains(groupStr, "$(TeamIdentifierPrefix)") {
					target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
						fmt.Sprintf("HIGH: Keychain Shared by Team ID: %s\nEXPLOITATION: All apps from same developer team can access. Attacker's app (same team) reads secrets. POC: Create app with same team ID, read keychain.\nIMPACT: Data accessible to developer's other apps (potentially malicious)", groupStr))
				}
			}
		}
	}

	// IMPROVED: Check for weak access level combined with app groups
	if appGroups, ok := ents["com.apple.security.application-groups"]; ok {
		if appGroupList, ok := appGroups.([]interface{}); ok && len(appGroupList) > 0 {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
				"HIGH RISK: App Groups Enabled + Keychain Sharing\nEXPLOITATION: Extensions and other grouped apps access shared keychain. Widget/extension reads auth tokens. POC: Access shared container, read serialized tokens.\nIMPACT: Extension isolation broken, sensitive data shared cross-app")
		}
	}
}

// ============================================
// NEW FEATURE 3: Custom URL Scheme Security Analysis
// ============================================

// AnalyzeURLSchemeValidation checks for unsafe URL scheme implementations
func AnalyzeURLSchemeValidation(info *AppInfo, binaryPath string, target *Target) {
	if len(info.CFBundleURLTypes) == 0 {
		return
	}

	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := string(content)
	baseName := filepath.Base(binaryPath)

	// Skip SDK code - only check app binaries, not 3rd-party frameworks (prevent false positives)
	sdk_patterns := []string{"FBSDK", "CleverTap", "MoEngage", "OneSignal", "Firebase",
		"GoogleAnalytics", "Amplitude", "Sentry", "Adjust", "AppsFlyer", "Mixpanel"}
	for _, sdk := range sdk_patterns {
		if strings.Contains(baseName, sdk) {
			return // Skip SDK code - false positive prevention
		}
	}

	for _, urlType := range info.CFBundleURLTypes {
		for _, scheme := range urlType.CFBundleURLSchemes {
			schemeStr := strings.ToLower(scheme)

			// IMPROVED: Flag 1 - No input validation detected WITH DETAILED POC
			if !strings.Contains(data, "validateURL") &&
				!strings.Contains(data, "sanitize") &&
				!strings.Contains(data, "validate.*URL") &&
				strings.Contains(data, "openURL") {
				target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
					Title:       fmt.Sprintf("Unvalidated URL Scheme Handler: %s://", scheme),
					Description: fmt.Sprintf("VULNERABILITY: URL scheme '%s://' has NO input validation. EXPLOITATION: Send '%s://payment?amount=-1' or '%s://search?q=<img src=x onerror=alert(1)>' - app processes without checking. IMPACT: Parameter injection, XSS, logic bypass.", scheme, scheme, scheme),
					FilePath:    filepath.Base(binaryPath),
					LineNumber:  0,
					Snippet:     fmt.Sprintf("POC: %s://action?param=VALUE' OR '1'='1\" - if params used in SQL queries = SQLi", scheme),
				})
			}

			// IMPROVED: Flag 2 - Auth-related schemes (CRITICAL RISK)
			dangerousPatterns := []string{"oauth", "auth", "login", "callback", "payment"}
			for _, pattern := range dangerousPatterns {
				if strings.Contains(schemeStr, pattern) {
					target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
						Title:       fmt.Sprintf("CRITICAL: Unvalidated Auth Scheme: %s:// (NO validation)", scheme),
						Description: fmt.Sprintf("CRITICAL VULNERABILITY: Auth scheme '%s://' unvalidated. EXPLOITATION: Attacker sends '%s://login?user=admin&bypass=true' - NO SERVER VERIFICATION. IMPACT: Account takeover, privilege escalation, fraudulent actions.", scheme, scheme),
						FilePath:    filepath.Base(binaryPath),
						LineNumber:  0,
						Snippet:     fmt.Sprintf("POC: %s://login?username=victim@email.com&token=ATTACKER_TOKEN&admin=true", scheme),
					})
					break
				}
			}

			// IMPROVED: Flag 3 - No whitelist validation WITH EXPLICIT POC
			if !strings.Contains(data, "allowedHosts") &&
				!strings.Contains(data, "whitelist") &&
				!strings.Contains(data, "allowlist") &&
				strings.Contains(data, scheme) {
				target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
					Title:       fmt.Sprintf("Missing Host Whitelist: %s://", scheme),
					Description: fmt.Sprintf("VULNERABILITY: No host/origin validation on '%s://' handler. EXPLOITATION: '%s://profile?remote_user=admin' OR '%s://deeplink?redirect=http://attacker.com/phishing'. IMPACT: Access unintended features, redirect attacks.", scheme, scheme, scheme),
					FilePath:    filepath.Base(binaryPath),
					LineNumber:  0,
					Snippet:     fmt.Sprintf("POC: %s://admin?elevation_required=false OR %s://bypass?security_check=no", scheme, scheme),
				})
			}
		}
	}
}

// ============================================
// NEW FEATURE 4: Background Activity Data Leak Detection
// ============================================

// DetectBackgroundActivityLeaks checks for sensitive operations in background
func DetectBackgroundActivityLeaks(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := string(content)

	// Pattern: URLSession with background config handling sensitive data
	backgroundPatterns := []struct {
		pattern     string
		description string
	}{
		{`backgroundSessionConfiguration`, "Background URLSession detected - ensure no sensitive data is transmitted"},
		{`beginBackgroundTask.*URLSession`, "Background data sync detected - verify data encryption in transit"},
		{`AppDelegate.*background.*API`, "Background API calls detected - check for data exfiltration"},
		{`didFinishLaunching.*fetch.*background`, "Background fetch on app launch - may leak data to analytics"},
	}

	for _, bp := range backgroundPatterns {
		if regex := regexp.MustCompile(bp.pattern); regex.MatchString(data) {
			target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
				Title:       "Potential Background Data Leak",
				Description: bp.description,
				FilePath:    filepath.Base(binaryPath),
				LineNumber:  0,
				Snippet:     bp.pattern,
			})
		}
	}
}

// ============================================
// NEW FEATURE 5: App Extension Security Analysis
// ============================================

// AnalyzeAppExtensionSecurity checks shared container and extension risks
func AnalyzeAppExtensionSecurity(ents map[string]interface{}, target *Target) {
	// Check for app groups (shared container)
	if appGroups, ok := ents["com.apple.security.application-groups"]; ok {
		if groupList, ok := appGroups.([]interface{}); ok {
			for _, g := range groupList {
				groupStr := fmt.Sprintf("%v", g)
				target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
					fmt.Sprintf("App Extension Shared Container: %s - Extension/App can intercept data", groupStr))
			}
		}
	}

	// Check for inter-app audio routing (vulnerable to interception)
	if _, ok := ents["com.apple.security.network"]; ok {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
			"Network framework entitlement - may allow inter-process data observation")
	}

	// Check for WidgetKit bundle (watchkit/siri intents)
	if _, ok := ents["com.apple.developer.widget-kit"]; ok {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
			"WidgetKit enabled - widget data may be accessible to other apps on lock screen")
	}
}

// ============================================
// BUG BOUNTY FEATURE 1: Keychain API Misuse Detection
// ============================================

// AnalyzeKeychainAPIUsage detects insecure keychain API usage patterns
func AnalyzeKeychainAPIUsage(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := string(content)
	baseName := filepath.Base(binaryPath)

	// Skip SDK code
	sdk_patterns := []string{"FBSDK", "CleverTap", "MoEngage", "OneSignal", "Firebase",
		"GoogleAnalytics", "Amplitude", "Sentry", "Adjust", "AppsFlyer"}
	for _, sdk := range sdk_patterns {
		if strings.Contains(baseName, sdk) {
			return
		}
	}

	// Pattern 1: kSecAttrAccessibleAlways (accessible while device locked)
	if strings.Contains(data, "kSecAttrAccessibleAlways") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "CRITICAL: Keychain Accessible While Locked (kSecAttrAccessibleAlways)",
			Description: "CRITICAL VULNERABILITY: Keychain item set to kSecAttrAccessibleAlways - readable even when device is locked. EXPLOITATION: Attacker with physical access OR Frida hook extracts credentials without unlock. Tokens stored with this attribute are always accessible. POC: frida hook SecItemAdd → extract kSecValueData from items with kSecAttrAccessibleAlways. IMPACT: Permanent credential theft, no device unlock required.",
			FilePath:    baseName,
			LineNumber:  0,
			Snippet:     "kSecAttrAccessibleAlways = tokens readable while locked or via Frida",
		})
	}

	// Pattern 2: kSecAttrAccessibleAlwaysThisDeviceOnly (accessible while device locked, but not in iCloud)
	if strings.Contains(data, "kSecAttrAccessibleAlwaysThisDeviceOnly") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "HIGH: Keychain Accessible While Locked (kSecAttrAccessibleAlwaysThisDeviceOnly)",
			Description: "HIGH VULNERABILITY: Keychain item set to kSecAttrAccessibleAlwaysThisDeviceOnly - readable when device is locked. EXPLOITATION: Physical device access or jailbreak can extract credentials without entering passcode. IMPACT: Credentials exposed to local attacks, reduced security posture.",
			FilePath:    baseName,
			LineNumber:  0,
			Snippet:     "kSecAttrAccessibleAlwaysThisDeviceOnly = tokens readable while locked",
		})
	}

	// Pattern 3: Missing kSecAttrAccessible entirely (defaults to insecure)
	if strings.Contains(data, "SecItemAdd") && !strings.Contains(data, "kSecAttrAccessible") {
		target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
			Title:       "MEDIUM: SecItemAdd Missing Accessibility Attribute",
			Description: "VULNERABILITY: SecItemAdd() call without kSecAttrAccessible attribute. Defaults to kSecAttrAccessibleWhenUnlockedThisDeviceOnly. RECOMMENDED: Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly explicitly for tokens/passwords. IMPACT: May use insecure default if implementation changed.",
			FilePath:    baseName,
			LineNumber:  0,
			Snippet:     "SecItemAdd() without explicit kSecAttrAccessible",
		})
	}
}

// ============================================
// BUG BOUNTY FEATURE 2: Hardcoded Secrets with Entropy Detection
// ============================================

// AnalyzeHardcodedSecrets detects high-entropy strings and known hardcoded secret patterns
func AnalyzeHardcodedSecrets(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}

	// Extract strings from binary
	data := ExtractStrings(content)
	lines := strings.Split(data, "\n")

	// Entropy-based detection for random-looking strings (likely secrets)
	foundSecrets := make(map[string]bool) // Deduplicate
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Only analyze reasonably long strings (20+ chars = possible secrets)
		if len(line) >= 20 && len(line) <= 200 {
			entropy := calculateEntropy(line)

			// Flag if entropy > 4.5 (highly random, suspicious)
			if entropy > 4.5 {
				// Skip common false positives
				if isCommonString(line) {
					continue
				}

				key := fmt.Sprintf("%s_entropy_%.2f", line, entropy)
				if !foundSecrets[key] {
					foundSecrets[key] = true
					target.Report.Findings.Secrets = append(target.Report.Findings.Secrets, Finding{
						Title:       "HIGH ENTROPY STRING (Possible Hardcoded Secret)",
						Description: fmt.Sprintf("SUSPICIOUS: Found high-entropy string (entropy: %.2f). Pattern indicates hardcoded secret: API key, token, password, or encryption key. Verify string '%s' is not sensitive data. IMPACT: If secret is exposed, attacker can authenticate as app.", entropy, line),
						FilePath:    filepath.Base(binaryPath),
						LineNumber:  0,
						Snippet:     line,
						Value:       line,
					})
				}
			}
		}
	}

	// Known secret patterns (extends existing secret scanning)
	additionalPatterns := []struct {
		name    string
		pattern *regexp.Regexp
		severity string
	}{
		{
			"Stripe Test Key",
			regexp.MustCompile(`sk_test_[0-9a-zA-Z]{20,}`),
			"HIGH",
		},
		{
			"JWT Token",
			regexp.MustCompile(`eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`),
			"CRITICAL",
		},
		{
			"MongoDB Connection String",
			regexp.MustCompile(`mongodb://[a-zA-Z0-9_:]+@[a-zA-Z0-9.-]+`),
			"CRITICAL",
		},
		{
			"Private RSA/EC Key",
			regexp.MustCompile(`-----BEGIN (RSA|EC) PRIVATE KEY-----`),
			"CRITICAL",
		},
	}

	for _, ap := range additionalPatterns {
		matches := ap.pattern.FindAllString(data, -1)
		for _, match := range matches {
			if !foundSecrets[match] {
				foundSecrets[match] = true
				target.Report.Findings.Secrets = append(target.Report.Findings.Secrets, Finding{
					Title:       fmt.Sprintf("%s: %s", ap.severity, ap.name),
					Description: fmt.Sprintf("%s: Hardcoded %s found in binary. This credential can be extracted and used to authenticate/compromise services. IMMEDIATE ACTION: Rotate this secret, revoke old tokens, generate new API keys.", ap.severity, ap.name),
					FilePath:    filepath.Base(binaryPath),
					LineNumber:  0,
					Snippet:     match,
					Value:       match,
				})
			}
		}
	}
}

// ============================================
// BUG BOUNTY FEATURE 3: Logging Data Leak Detection
// ============================================

// AnalyzeLoggingStatements detects logging calls that expose sensitive data
func AnalyzeLoggingStatements(binaryPath string, target *Target) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	data := ExtractStrings(content)
	lines := strings.Split(data, "\n")

	// Patterns that indicate logging with sensitive data
	sensitivePatterns := []struct {
		logPattern string
		logType    string
		severity   string
	}{
		// NSLog/print with credentials
		{`(?i)NSLog.*password|NSLog.*passwd|NSLog.*pwd`, "NSLog with password", "CRITICAL"},
		{`(?i)print.*password|print.*credentials|print.*token`, "print() with password", "CRITICAL"},
		{`(?i)NSLog.*token|NSLog.*auth.*token|NSLog.*Bearer`, "NSLog with auth token", "CRITICAL"},
		{`(?i)print.*Bearer|print.*bearer.*token|print.*access_token`, "print() with Bearer token", "CRITICAL"},
		{`(?i)NSLog.*credit.*card|NSLog.*cc.*number|NSLog.*cardNumber`, "NSLog with payment data", "CRITICAL"},
		{`(?i)NSLog.*ssn|NSLog.*social.*security|NSLog.*\..*\d{3}.*\d{2}.*\d{4}`, "NSLog with SSN/PII", "CRITICAL"},
		{`(?i)debugPrint.*password|debugPrint.*token|debugPrint.*secret`, "debugPrint with sensitive data", "HIGH"},
		{`(?i)api.*key.*=|apiKey.*=|API_KEY`, "API key assignment (may be logged)", "HIGH"},
		{`(?i)print.*secret|print.*apiKey|print.*api_key`, "print() with API key", "HIGH"},
	}

	foundIssues := make(map[string]bool)
	for i, line := range lines {
		line = strings.TrimSpace(line)

		for _, sp := range sensitivePatterns {
			pattern := regexp.MustCompile(sp.logPattern)
			if pattern.MatchString(line) {
				key := fmt.Sprintf("%d_%s", i, sp.logType)
				if !foundIssues[key] {
					foundIssues[key] = true
					target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
						Title:       fmt.Sprintf("%s: Sensitive Data Logged", sp.severity),
						Description: fmt.Sprintf("%s: Found logging statement that may expose %s. EXPLOITATION: Inspect app logs/crash reports/system logs to extract credentials. Logging statements are visible in: crash reports, unified logs (Console.app), Xcode debugging. IMPACT: Credentials exposed in logs, visible to users via console, sent in crash reports.", sp.severity, sp.logType),
						FilePath:    filepath.Base(binaryPath),
						LineNumber:  i + 1,
						Snippet:     line,
					})
				}
			}
		}
	}
}

// ============================================
// BUG BOUNTY FEATURE 4: Entitlements Configuration Analysis
// ============================================

// AnalyzeEntitlementsMisconfig checks for insecure entitlements settings
func AnalyzeEntitlementsMisconfig(ents map[string]interface{}, target *Target) {
	if ents == nil {
		return
	}

	// Pattern 1: com.apple.security.get-task-allow = true (Debug flag)
	if taskAllow, ok := ents["com.apple.security.get-task-allow"].(bool); ok && taskAllow {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
			"CRITICAL SECURITY ISSUE: get-task-allow = true\nDEBUG FLAG ENABLED IN PRODUCTION BUILD: This entitlement allows ANY process to attach debugger to app. EXPLOITATION: Frida/LLDB can attach and instrument code. SHOULD ONLY BE: true in debug builds, false in production. IMPACT: Complete app instrumentation, all functions can be hooked.")
	}

	// Pattern 2: Wildcard in application-identifier
	if appId, ok := ents["application-identifier"].(string); ok {
		if strings.Contains(appId, "*") || appId == "*" {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
				fmt.Sprintf("ALERT: Wildcard in app identifier: %s - May allow execution of any bundle ID", appId))
		}
	}

	// Pattern 3: Overpermissive file access
	fileBrowserPaths := []string{
		"com.apple.security.files.user-selected.read-write",
		"com.apple.security.files.downloads.read-write",
	}

	for _, pathEnt := range fileBrowserPaths {
		if access, ok := ents[pathEnt].(bool); ok && access {
			target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
				fmt.Sprintf("HIGH: Broad file access enabled (%s) - App can read/write all user files. Potential data exfiltration risk.", pathEnt))
		}
	}

	// Pattern 4: Missing data protection
	if _, ok := ents["com.apple.developer.default-data-protection"]; !ok {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
			"MEDIUM: Missing default data protection entitlement - Files may not have encryption at rest")
	}

	// Pattern 5: Network securityPolicy too permissive
	if _, ok := ents["com.apple.security.network.client"]; ok {
		target.Report.Findings.Misconfigurations = append(target.Report.Findings.Misconfigurations,
			"MEDIUM: Network client entitlement enabled - App can make outbound connections. Verify not used for data exfiltration.")
	}
}

// ============================================
// BUG BOUNTY FEATURE 5: Network Security Configuration Analysis
// ============================================

// AnalyzeNetworkSecurityConfig checks ATS and network security settings
func AnalyzeNetworkSecurityConfig(info *AppInfo, ents map[string]interface{}, target *Target) {
	if info == nil {
		return
	}

	// Pattern 1: Advanced ATS bypass detection
	if info.NSAppTransportSecurity != nil {
		ats := info.NSAppTransportSecurity

		// Check for NSAllowsLocalNetworking (can downgrade to HTTP locally)
		if allowLocal, ok := ats["NSAllowsLocalNetworking"].(bool); ok && allowLocal {
			target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
				Title:       "HIGH: NSAllowsLocalNetworking Enabled",
				Description: "VULNERABILITY: NSAllowsLocalNetworking = true allows cleartext HTTP to local addresses. EXPLOITATION: MITM on local network (same WiFi) can intercept traffic. IMPACT: Credentials and data exposed if communicating with local servers.",
				FilePath:    "Info.plist",
				LineNumber:  0,
				Snippet:     "NSAllowsLocalNetworking = true",
			})
		}

		// Check exception domains for overpermissive settings
		if exDomains, ok := ats["NSExceptionDomains"].(map[string]interface{}); ok {
			for domain, settings := range exDomains {
				if sMap, ok := settings.(map[string]interface{}); ok {
					// Domain allows insecure HTTP
					if insecure, ok := sMap["NSExceptionAllowsInsecureHTTPLoads"].(bool); ok && insecure {
						target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
							Title:       fmt.Sprintf("HIGH: Cleartext HTTP Exception for %s", domain),
							Description: fmt.Sprintf("VULNERABILITY: ATS exception allows HTTP for %s. EXPLOITATION: MITM attack intercepts traffic to/from %s. IMPACT: Credentials, API responses, and user data exposed in transit.", domain, domain),
							FilePath:    "Info.plist",
							LineNumber:  0,
							Snippet:     fmt.Sprintf("NSExceptionAllowsInsecureHTTPLoads = true for %s", domain),
						})
					}

					// Domain disables forward secrecy
					if !disablePFS(sMap) {
						target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
							Title:       fmt.Sprintf("MEDIUM: Forward Secrecy Disabled for %s", domain),
							Description: "VULNERABILITY: Forward secrecy disabled - old traffic can be decrypted if key stolen. IMPACT: Historical data exposure if long-term keys compromised.",
							FilePath:    "Info.plist",
							LineNumber:  0,
							Snippet:     fmt.Sprintf("NSExceptionRequiresForwardSecrecy = false for %s", domain),
						})
					}
				}
			}
		}
	}

	// Pattern 2: Certificate pinning detection
	content, err := os.ReadFile(target.BinaryPath)
	if err == nil {
		data := ExtractStrings(content)

		// Check for pinning indicator absence
		pinningIndicators := []string{"AFSecurityPolicy", "ServerTrustManager", "CertificatePinning", "PublicKey.*pin"}
		hasPinning := false
		for _, indicator := range pinningIndicators {
			if match, _ := regexp.MatchString(indicator, data); match {
				hasPinning = true
				break
			}
		}

		// Only flag if ATS is disabled OR exceptions exist
		hasATSBypass := false
		if info.NSAppTransportSecurity != nil {
			if allow, ok := info.NSAppTransportSecurity["NSAllowsArbitraryLoads"].(bool); ok && allow {
				hasATSBypass = true
			}
		}

		if hasATSBypass && !hasPinning {
			target.Report.Findings.CodeIssues = append(target.Report.Findings.CodeIssues, Finding{
				Title:       "CRITICAL: ATS Disabled + No Certificate Pinning",
				Description: "CRITICAL VULNERABILITY: App disables ATS but has no certificate pinning. EXPLOITATION: Complete MITM on any network. Attacker presents fake certificate, intercepts all HTTPS traffic. IMPACT: Complete compromise - steal credentials, modify API responses, inject malware.",
				FilePath:    "Info.plist + Binary",
				LineNumber:  0,
				Snippet:     "NSAllowsArbitraryLoads = true + no pinning = total MITM vulnerability",
			})
		}
	}
}

// ============================================
// Helper Functions for Bug Bounty Detectors
// ============================================

// calculateEntropy calculates Shannon entropy of a string (0.0 to ~5.0)
// Higher entropy (~4.5+) suggests random/encrypted data (possible secrets)
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count frequency of each byte
	freqMap := make(map[rune]int)
	for _, ch := range s {
		freqMap[ch]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, freq := range freqMap {
		p := float64(freq) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// isCommonString filters out frequently occurring non-secret strings
func isCommonString(s string) bool {
	commonSubstrings := []string{
		"com.apple", "apple.com", "https://", "http://", ".com", ".org", ".net",
		"0123456789", "abcdefghij", "version", "copyright", "license",
		"framework", "bundle", "identifier", "application", "service",
		"unknown", "undefined", "localhost", "127.0.0.1", "user_agent",
	}

	lower := strings.ToLower(s)
	for _, substr := range commonSubstrings {
		if strings.Contains(lower, substr) {
			return true
		}
	}

	return false
}

// disablePFS checks if forward secrecy is disabled
func disablePFS(sMap map[string]interface{}) bool {
	if pfs, ok := sMap["NSExceptionRequiresForwardSecrecy"].(bool); ok && !pfs {
		return true
	}
	return false
}
