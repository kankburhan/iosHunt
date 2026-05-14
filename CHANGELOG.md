# Changelog

All notable changes to iOSHunt will be documented in this file.

## [v1.15.0] - 2026-05-14

### Added (Phase 27: Bug Bounty-Grade Vulnerability Detectors)

Based on real-world research from **HackerOne, Bugcrowd, YesWeHack, and Intigriti**, added 7 new vulnerability analysis modules targeting **Medium-Critical** severity findings commonly accepted in bug bounty programs.

#### Detector 1: WebView Security Analysis (MASVS-PLATFORM)
- Detects `WKWebView` + `evaluateJavaScript` without input sanitization (JS bridge injection)
- Flags `loadHTMLString` with dynamic content (stored XSS risk)
- Identifies unvalidated `WKScriptMessageHandler` (native bridge abuse)
- Detects deprecated `UIWebView` usage (no process isolation, Apple rejection)
- Severity: Critical-High

#### Detector 2: Privacy Manifest Compliance (MASVS-PLATFORM)
- Checks for `PrivacyInfo.xcprivacy` in app bundle
- Detects Required Reason API usage (`UserDefaults`, `mach_absolute_time`, `systemUptime`, `creationDate`, `fstat`, `activeInputModes`) without a manifest
- App Store rejection risk + privacy violation flagging
- Severity: Medium-High

#### Detector 3: Biometric Authentication Bypass (MASVS-AUTH)
- Detects `deviceOwnerAuthenticationWithBiometrics` without passcode fallback
- Flags missing `evaluatedPolicyDomainState` check (biometric replay/enrollment attack)
- Identifies `LAContext` without `invalidate()` call (session reuse)
- Severity: Medium-High

#### Detector 4: Deprecated/Unsafe API Detection (MASVS-CODE)
- Detects `NSURLConnection` (deprecated networking, no HTTP/2)
- Flags `unarchiveObjectWithFile` (unsafe deserialization variant)
- Identifies `CC_MD2`, `CC_MD4` (broken hash algorithms)
- Detects `kCCAlgorithm3DES` (Sweet32 vulnerable), `kCCKeySizeAES128` (consider AES-256)
- Severity: Medium-High

#### Detector 5: Clipboard/Pasteboard Data Leakage (MASVS-STORAGE)
- Detects `UIPasteboard.general` with sensitive data context (password/token/credential)
- Flags missing `expirationDate` on clipboard items (indefinite data persistence)
- Cross-app clipboard access risk assessment
- Severity: Medium-High

#### Detector 6: Screenshot/Background Caching Protection (MASVS-STORAGE)
- Detects missing `applicationWillResignActive` snapshot blur/overlay
- Flags absence of `userDidTakeScreenshotNotification` monitoring
- Only triggers for apps handling sensitive data (auth/financial context)
- Severity: Medium

#### Detector 7: Supply Chain / SDK Vulnerability Scanning (MASVS-CODE)
- Detects known vulnerable SDK patterns: AFNetworking 2.x (CVE-2015-3996), React Native debug bridge, Flutter debug mode
- Flags debug/analytics SDKs left in production (Firebase debug, Crashlytics PII logging)
- Scans embedded frameworks for debug/test/mock artifacts
- Reports large framework counts for audit
- Severity: Medium-High

### Modified
- `core/recon.go`: Added 7 new analysis functions and integrated into StaticAnalyze() pipeline (+510 LOC)
- `core/update.go`: Version bumped to v1.15.0
- `CHANGELOG.md`: Added v1.14.2 and v1.15.0 entries
- `ATTACK_SCENARIOS.md`: Added 3 new attack scenarios (WebView XSS, Biometric Bypass, Clipboard Theft)
- `IMPLEMENTATION_COMPLETE.md`: Updated with Phase 27 detectors
- `NEW_FEATURES_DOCUMENTATION.md`: Added all 7 new detector documentation
- `TEST_NEW_FEATURES.sh`: Added testing steps for new detectors
- `README.md`: Updated feature list, version, and detector count

### Performance
- New detectors add ~3-5% analysis time (binary string scanning)
- No regression on existing analysis modules
- Third-party SDK filtering prevents false positive explosion

---

## [v1.14.2] - 2026-05-14

### Fixed
- Embedded all Frida/Ghidra scripts into Go binary using `//go:embed` (no more external script dependency)
- Added `core/assets.go` with `ExtractAsset()` helper for runtime script extraction
- Fixed Ghidra headless analysis path resolution for macOS Homebrew installations
- Resolved Java Runtime dependency detection for Ghidra pipeline

### Changed
- `cmd/recon.go`: Updated Ghidra script lookup to use embedded assets via `core.ExtractAsset`
- `core/frida.go`: Updated `GetAssetScript` to use embedded filesystem
- Cleaned up IDE warnings across multiple files:
  - `core/mcp.go`: Removed unused parameters, fixed redundant Sprintf
  - `core/recon.go`: Removed unused `hasString` function
  - `core/autopentest.go`: Refactored if-else chains to switch statements
  - `core/dataflow.go`: Cleaned up unused variables and parameters
  - `core/evidence.go`: Removed unused `strings` import and `summarizeEvidence` method

### Added
- `core/assets/` directory with all embedded scripts (23 files)
- `core/assets.go` with `//go:embed` directive and `ExtractAsset()` function

---

## [v1.12.0] - 2026-02-27

### Added (Phase 24, 25 & 26)

#### Phase 24: Data Flow Analysis Engine
- Complete Data Flow Analysis (DFA) engine for tracing sensitive data flows
- String-based flow detection with multi-factor confidence scoring algorithm
- Binary-level heuristic analysis for detecting data flow patterns in compiled code
- 5 vulnerability flow types detected:
  - Secrets → Logging (CRITICAL severity)
  - Secrets → Network endpoints (CRITICAL severity)
  - Secrets → Weak Keychain storage (HIGH severity)
  - Secrets → Insecure storage (HIGH severity)
  - Secrets → Clipboard/Pasteboard (HIGH severity)
- Automatic taint graph generation and JSON/Markdown/HTML report integration
- Real-world testing: 42,480 flows detected on 208MB AirAsia Mobile app
- Remediation suggestions for each detected data flow vulnerability

#### Phase 25: AI-Powered Vulnerability Analysis
- New `ioshunt analyze` command for AI-powered vulnerability assessment
- OpenAI API integration with support for OpenAI-compatible endpoints
- Configuration management system (`ioshunt config`) for API credentials
- Support for streaming responses and multiple AI models (GPT-4, GPT-4o, etc)
- Frida device detection system for dynamic analysis preparation

#### Phase 26: Advanced Security Detectors (5 Bug Bounty-Based Features)
- **Feature 1: Keychain API Misuse Detection**
- **Feature 2: Hardcoded Secrets with Entropy Analysis**
- **Feature 3: Logging Data Leak Detection**
- **Feature 4: Entitlements Misconfiguration Analysis**
- **Feature 5: Insecure Network Configuration Analysis**

### Performance
- Data Flow Analysis processing: ~25 seconds for 208MB apps, ~8 seconds for smaller apps
- Zero performance regression on existing analysis modules

---

## [v1.11.0] - Previous Release

### Features
- Ghidra integration for binary analysis
- Deep link detection and security analysis
- Binary scanning optimizations
- Previous 5 advanced security detectors

---

## [v1.2.0] - Earlier Release

### Features
- Fastlane integration
- Auto-release workflow
- Various security analysis improvements

---
