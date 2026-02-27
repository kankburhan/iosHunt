# Changelog

All notable changes to iOSHunt will be documented in this file.

## [v1.12.0] - 2026-02-27

### Added (Phase 24 & 25)

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

### Modified
- `core/recon.go`: Integrated AnalyzeDataFlow() into StaticAnalyze() pipeline
- `core/report.go`: Extended Finding struct with dataflow fields (DataFlowNodeID, IsTaintSource, IsTaintSink, TaintPaths)
- `README.md`: Updated feature list and usage examples for v1.12.0

### Performance
- Data Flow Analysis processing: ~25 seconds for 208MB apps (AirAsia), ~8 seconds for smaller apps (Meesho)
- Zero performance regression on existing analysis modules
- Efficient confidence scoring algorithm (weighted multi-factor analysis)

### Testing
- Tested on com.airasia.mobile: 42,480 data flow paths detected
- Tested on com.meesho.Meesho: 468 data flow paths detected
- Verified AI config/show/analyze commands working correctly
- Verified Frida device detection properly exported
- Verified all components compile without errors

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
