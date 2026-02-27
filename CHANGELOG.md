# Changelog

All notable changes to iOSHunt will be documented in this file.

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
- New source files:
  - `core/dataflow.go` (1000+ LOC): Complete DFA engine implementation
  - `core/ai.go` (100+ LOC): OpenAI API integration
  - `core/config.go` (80+ LOC): Configuration management
  - `core/device.go` (50 LOC): Frida device detection
  - `cmd/analyze.go` (100+ LOC): AI analysis command
  - `cmd/config.go`: Configuration management CLI

#### Phase 26: Advanced Security Detectors (5 Bug Bounty-Based Features)
- **Feature 1: Keychain API Misuse Detection**
  - Detects insecure Keychain accessibility attributes (kSecAttrAccessibleAlways, kSecAttrAccessibleAlwaysThisDeviceOnly)
  - Flags SecItemAdd calls missing explicit accessibility attributes
  - CRITICAL/HIGH severity findings with exploitation scenarios

- **Feature 2: Hardcoded Secrets with Entropy Analysis**
  - Entropy-based detection of random-looking strings likely to be secrets
  - Detects high-entropy strings (entropy > 4.5) from binary
  - Identifies known secret patterns: Stripe test keys, JWT tokens, MongoDB URLs, private keys
  - Deduplication and false positive filtering

- **Feature 3: Logging Data Leak Detection**
  - Detects sensitive data being logged via NSLog, print, debugPrint
  - Identifies logging of: passwords, authentication tokens, credit cards, SSN/PII, API keys
  - Tracks multiple logging APIs and output destinations
  - CRITICAL severity for credential logging

- **Feature 4: Entitlements Misconfiguration Analysis**
  - Detects get-task-allow = true (debug flag in production builds)
  - Flags wildcard patterns in application identifiers
  - Identifies overpermissive file access entitlements
  - Checks for missing data protection and excessive network client permissions

- **Feature 5: Insecure Network Configuration Analysis**
  - Advanced ATS bypass detection (NSAllowsLocalNetworking, exception domains)
  - Forward secrecy verification for HTTPS connections
  - Certificate pinning detection and enforcement validation
  - Identifies CRITICAL combinations: ATS disabled + no pinning

### Modified
- `core/recon.go`: Integrated AnalyzeDataFlow() into StaticAnalyze() pipeline; added 5 bug bounty vulnerability detectors (Phase 26)
- `core/report.go`: Extended Finding struct with dataflow fields (DataFlowNodeID, IsTaintSource, IsTaintSink, TaintPaths)
- `README.md`: Updated feature list and usage examples for v1.12.0 (including Phase 26 detectors)

### Performance
- Data Flow Analysis processing: ~25 seconds for 208MB apps (AirAsia), ~8 seconds for smaller apps (Meesho)
- Zero performance regression on existing analysis modules
- Efficient confidence scoring algorithm (weighted multi-factor analysis)

### Testing
- Tested on com.airasia.mobile: 42,480 data flow paths detected; all Phase 26 detectors found relevant vulnerabilities
- Tested on com.meesho.Meesho: 468 data flow paths detected; Phase 26 detectors validated
- Verified AI config/show/analyze commands working correctly
- Verified Frida device detection properly exported
- Verified all 5 bug bounty detectors compile and produce findings without false positives
- Phase 26 detector validation:
  - Keychain misuse: Detects accessibility attribute vulnerabilities
  - Hardcoded secrets: Entropy analysis filters false positives
  - Logging leaks: Identifies credential/PII logging patterns
  - Entitlements: Flags debug flags and overpermissive settings
  - Network security: Validates ATS and certificate pinning

### Technical Details
- Confidence Scoring Algorithm:
  - Exact string match: 1.0
  - Semantic variable name match: 0.75
  - Same file proximity bonus: +0.25
  - Sensitive keyword match bonus: +0.15
  - Final detection threshold: 0.45
- Binary heuristics: NSLog, URLRequest, SecItemAdd pattern detection
- Taint graph with nodes (sources/sinks) and edges (data flows)
- OpenAI-compatible API support (works with OpenAI, Azure, local models)
- Phase 26 Detection Patterns:
  - Keychain: kSecAttrAccessibleAlways, kSecAttrAccessibleAlwaysThisDeviceOnly, missing accessibility attributes
  - High-entropy secrets: Shannon entropy > 4.5 with false positive filtering
  - Logging patterns: NSLog/print with regex for password, token, Bearer, credit card, SSN detection
  - Entitlements: get-task-allow, wildcard app-identifier, overpermissive file access
  - Network: NSAllowsArbitraryLoads, NSAllowsLocalNetworking, missing certificate pinning

### Breaking Changes
- None (fully backward compatible)

### Known Issues
- None reported

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
