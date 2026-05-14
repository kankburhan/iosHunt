# iOSHunt

**One Command iOS Pentesting Pipeline — Bug Bounty-Grade Vulnerability Detection with Live Exploit Verification & Auto-Reproduction**

`ioshunt` is a comprehensive CLI tool designed to automate the entire lifecycle of an iOS application security assessment. From downloading the IPA to AI-driven autonomous pentesting with **runtime evidence capture**, it handles everything so you can focus on finding vulnerabilities.

## Features (v1.15.0)

### 1. Automation Pipeline
-   **Download**: Fetches IPAs from the App Store (handles auth & country selection).
-   **Injection**: Automatically inserts `FridaGadget.dylib`.
-   **Resigning**: Resigns the app with your development profile.
-   **Installation**: Deploys to connected devices via `ios-deploy` or `ideviceinstaller`.
-   **Non-JB Sideload (NEW)**: Layered installer with `ideviceinstaller` (libimobiledevice), `ios-deploy`, and AltStore fallback.

### 2. Static Analysis (26-Phase Recon Engine + 17 Specialized Detectors)
-   **Secrets Scanning**: Detects hardcoded keys, tokens, and private data (12+ patterns with entropy analysis).
-   **Misconfigurations**: Checks `Info.plist` (ATS, File Sharing) and Entitlements (`get-task-allow`).
-   **Binary Security**: Verifies PIE, ARC, Stack Canaries, and Encryption status.
-   **Data Flow Analysis**: Taint tracking from sources (secrets) to sinks (logging, network, storage). 42K+ flows on real apps.
-   **Crypto Issues**: Weak algorithms, unsafe random generation, ECB mode detection.
-   **Code Injection**: SQL injection, XSS, format string, and deserialization vulnerabilities.
-   **Advanced Detectors**: Keychain API misuse, logging data leaks, entitlements misconfiguration, insecure network config.
-   **Bug Bounty Detectors (NEW v1.15.0)**: WebView XSS, biometric bypass, clipboard leaks, privacy manifest, deprecated APIs, snapshot protection, SDK supply chain scanning.
-   **Attack Chain Detection (NEW)**: Identifies combinations of vulnerabilities that can be chained for maximum impact.
-   **Reporting**: JSON, Markdown, and HTML reports with full taint graph visualization.

### 3. AI-Powered Analysis
-   **AI Assessment**: Sends reports to AI for deep vulnerability analysis and remediation.
-   **Multi-Provider**: Works with OpenAI (GPT-4o), Anthropic (Claude), Ollama, Groq, and any OpenAI-compatible API.
-   **OWASP MASVS Mapping**: Automated categorization of findings.

### 4. AI Auto-Pentest (NEW)
Fully autonomous AI-driven penetration testing. The AI agent orchestrates the entire assessment:

-   **MCP Server Mode**: Connect to Claude Desktop as an MCP tool server — Claude becomes your AI pentester.
-   **Standalone Mode**: Run `ioshunt autopentest` for a self-contained AI agent loop with tool-use.
-   **19 Tools**: Recon, findings analysis, Frida script generation, live verification, on-device reproduction, evidence capture, non-JB sideload, reporting, and more.
-   **Agentic Loop**: AI decides what to analyze next, drills into findings, generates PoCs, verifies live APIs, reproduces on device, and writes the final report.
-   **Multi-API Support**: Works with Claude API (native tool-use), GPT-4 (function calling), or any OpenAI-compatible endpoint.

### 5. Dynamic Analysis (Runtime)
-   **Frida Integration**: Attaches to running processes with auto device detection.
-   **Bypasses**: SSL Pinning, Biometrics, Jailbreak Detection, iXGuard/Anti-Debugging.
-   **Forensics**: Dumps Keychain, Cookies, and NSUserDefaults.
-   **Monitoring**: Real-time crypto operations, HTTP headers, URL scheme, NSCoding, and Keychain monitoring.
-   **Custom Scripts**: Plugin system for custom Frida scripts.

### 6. Live Exploit Verification (NEW — Phase 27)
Actively probe findings against real services to confirm exploitability — no more guessing.
-   **API Key Validation**: Provider-specific probes for Google, Stripe, GitHub, Slack, Mapbox, SendGrid, OpenAI, Firebase.
-   **URL/Endpoint Probes**: Hits exposed URLs and inspects responses for sensitive data leakage.
-   **Status Tracking**: Each finding flagged `CONFIRMED`, `DEAD`, or `UNREACHABLE`.
-   **Evidence**: Raw HTTP responses saved per finding for the final report.

### 7. Auto-Reproduction on Device (NEW — Phase 28)
Static findings get reproduced live on the connected device — non-JB friendly via FridaGadget.
-   **Category-Aware Hooks**: secret/url → network, keychain → SecItem*, storage → NSUserDefaults/NSFileManager, crypto → CCCrypt/MD5/PBKDF, url_scheme → openURL.
-   **Standard Signal**: `[REPRO_HIT]` markers parsed from Frida output mark `Finding.Reproduced=true`.
-   **Evidence Capture**: Screenshots (`idevicescreenshot`), network capture (`rvictl` + `tcpdump`), Frida transcripts.
-   **Bundled Output**: Per-session evidence dirs auto-tar'd into a single `.tar.gz` for delivery.

### 8. Non-Jailbroken Sideload (NEW — Phase 29)
Layered installer for stock iOS — no jailbreak required.
-   **Primary**: `ideviceinstaller` (libimobiledevice).
-   **Fallback Chain**: `ios-deploy` → AltStore/SideStore.
-   **Pair Helper**: One-shot `sideload pair` flow, handles "Trust" prompt.
-   **Device Mgmt**: List devices, list installed apps, uninstall by bundle ID.

### 9. Utilities
-   **Doctor**: Verifies environment health and dependencies.
-   **Update**: Self-updating binary.
-   **Clean**: Workspace cleanup.
-   **Config**: Manage AI API credentials and settings.

## Installation

### Prerequisites
-   macOS (Required for `codesign`, `security`)
-   Go 1.24+
-   `frida`, `objection`, `ideviceinstaller`, `ios-deploy`
-   libimobiledevice suite: `idevice_id`, `idevicepair`, `ideviceinstaller`, `idevicescreenshot`
-   `rvictl` + `tcpdump` — for pcap capture (included with Xcode)
-   AltStore/SideStore (optional, fallback sideload method)

```bash
# Install libimobiledevice + ideviceinstaller via Homebrew
brew install libimobiledevice ideviceinstaller ios-deploy
```

### Quick Install (via go install)
```bash
# Install latest release
go install github.com/kankburhan/iosHunt@latest

# Verify installation
ioshunt --help
```

### Build from Source
```bash
git clone https://github.com/kankburhan/iosHunt.git
cd iosHunt
go install

# Or directly from repo
go install github.com/kankburhan/iosHunt@master
```

## Usage

### Full Pipeline
Run the complete workflow (Download -> Inject -> Resign -> Install -> Attach):
```bash
ioshunt com.example.app
```

### Static Analysis
```bash
ioshunt recon com.example.app
ioshunt report com.example.app --format html
```

### AI-Powered Vulnerability Assessment
```bash
# Configure AI provider
ioshunt config set ai_api_key sk-xxxx
ioshunt config set ai_model gpt-4o
ioshunt config show

# Analyze latest scan with AI
ioshunt analyze com.example.app
```

### AI Auto-Pentest (Standalone)
```bash
# Configure AI (Anthropic Claude recommended for best tool-use)
ioshunt config set ai_base_url https://api.anthropic.com/v1
ioshunt config set ai_api_key sk-ant-xxxx
ioshunt config set ai_model claude-sonnet-4-5-20241022

# Launch autonomous pentest
ioshunt autopentest com.example.app

# With more iterations
ioshunt autopentest com.example.app --rounds 20

# Override model
ioshunt autopentest com.example.app --model gpt-4o
```

### AI Auto-Pentest (Claude Desktop MCP)
Connect iOSHunt as an MCP server to Claude Desktop for interactive AI pentesting.

**1. Add to Claude Desktop config** (`~/.claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ioshunt": {
      "command": "ioshunt",
      "args": ["mcp"]
    }
  }
}
```

**2. Restart Claude Desktop**, then ask:
```
"Perform a full security assessment of com.example.app"
"Find all hardcoded API keys in the AirAsia app and check if they're live"
"Generate Frida scripts to bypass SSL pinning and monitor keychain access"
"Create a professional pentest report for the latest scan"
```

**Available MCP Tools (19):**
| Tool | Description |
|------|-------------|
| `ios_recon` | Full 26-phase static analysis |
| `ios_download_ipa` | Download IPA from App Store |
| `ios_get_findings` | Query findings by category/severity |
| `ios_get_app_info` | App metadata & binary security |
| `ios_generate_frida_script` | AI-generated Frida scripts |
| `ios_attach_frida` | Runtime instrumentation |
| `ios_dump_runtime` | Keychain/cookies/defaults extraction |
| `ios_check_device` | Device connectivity check |
| `ios_generate_report` | Multi-format report generation |
| `ios_inject_and_resign` | Frida gadget injection + resign |
| `ios_install_app` | Device installation |
| `ios_pentest_status` | Session status & next actions |
| `ios_search_strings` | Pattern search in app binaries |
| `ios_exploit_verify` | Exploitability verification |
| `ios_live_verify` | **NEW** — Probe findings live, mark CONFIRMED/DEAD/UNREACHABLE |
| `ios_reproduce_finding` | **NEW** — Auto-repro findings on device via Frida category hooks |
| `ios_capture_evidence` | **NEW** — Screenshot / netcap (rvictl+tcpdump) / bundle tar.gz |
| `ios_sideload` | **NEW** — Non-JB install via libimobiledevice fallback chain |
| `ios_auto_hunt` | **NEW** — Full pipeline: recon → verify → repro → evidence bundle |

### Non-JB Full Pipeline (Recommended for Stock Devices)
End-to-end workflow for a non-jailbroken device — pair once, then fully automated:
```bash
# 1. Prepare device (tap "Trust" on screen when prompted)
ioshunt sideload pair

# 2. Run static analysis
ioshunt recon com.target.app

# 3. Inject FridaGadget + resign
ioshunt inject com.target.app
ioshunt resign com.target.app

# 4. Sideload the patched IPA
ioshunt sideload install -i target_resigned.ipa --launch

# 5. Full autohunt: live verify → on-device repro → evidence bundle
ioshunt autohunt com.target.app --skip-recon --duration 30 --netcap
```

### Live Exploit Verification
Actively probe hardcoded secrets and URLs against real services:
```bash
# Verify all HIGH+ findings
ioshunt livetest com.target.app

# Verify all severities, limit to 50
ioshunt livetest com.target.app --severity LOW --max 50

# Output to custom dir
ioshunt livetest com.target.app --output-dir ./evidence/live
```

### On-Device Reproduction
Attach Frida hooks tailored per finding category to confirm issues at runtime:
```bash
# Reproduce all HIGH+ findings (default)
ioshunt reproduce com.target.app

# Reproduce a single category
ioshunt reproduce com.target.app --category keychain --duration 30

# Reproduce a specific finding by ID
ioshunt reproduce com.target.app --id FIND-0042 --verbose

# Spawn the app instead of attaching
ioshunt reproduce com.target.app --spawn
```

### Non-JB Device Management
```bash
ioshunt sideload list                          # List connected devices
ioshunt sideload pair                          # Pair device (tap Trust first)
ioshunt sideload install -i app.ipa --launch  # Install + launch
ioshunt sideload apps                          # List installed user apps
ioshunt sideload uninstall -b com.target.app  # Uninstall by bundle ID
```

### Full Autonomous Hunt (autohunt)
Single command that chains all phases together:
```bash
# Full run: recon + live verify + on-device repro + pcap + bundle
ioshunt autohunt com.target.app --netcap

# Skip recon (reuse last report)
ioshunt autohunt com.target.app --skip-recon

# Only HIGH/CRITICAL, 45s per repro script
ioshunt autohunt com.target.app --severity HIGH --duration 45

# Target a specific device UDID
ioshunt autohunt com.target.app --device 00008101-XXXXXXXXXXXX
```

### Runtime Analysis
```bash
# Attach with SSL Pinning and Jailbreak Bypass
ioshunt attach "App Name" --ssl --bypass

# Monitor Crypto Operations and Headers
ioshunt attach "App Name" --crypto --headers

# Monitor Keychain and URL Schemes
ioshunt attach "App Name" --keychain-monitor --url-scheme-monitor
```

### Forensics
```bash
ioshunt dump keychain com.example.app
ioshunt dump cookies com.example.app
ioshunt dump defaults com.example.app
```

### Maintenance
```bash
ioshunt doctor    # Check environment
ioshunt update    # Update tool
ioshunt clean     # Clean workspace
```

## Architecture

```
ioshunt
├── cmd/                      # CLI commands (Cobra)
│   ├── root.go              # Main pipeline orchestrator
│   ├── recon.go             # Static analysis command
│   ├── analyze.go           # AI analysis command
│   ├── autopentest.go       # AI auto-pentest command
│   ├── mcp.go               # MCP server command
│   ├── attach.go            # Frida attachment
│   ├── dump.go              # Forensic extraction
│   ├── livetest.go          # NEW — Live exploit verification CLI
│   ├── reproduce.go         # NEW — On-device reproduction CLI
│   ├── sideload.go          # NEW — Non-JB sideload CLI
│   ├── autohunt.go          # NEW — Full autonomous hunt pipeline
│   ├── report_loader.go     # NEW — Shared helper: loadLatestReport()
│   └── ...
├── core/                     # Core modules
│   ├── recon.go             # 26-phase static analysis engine + 17 detectors (2200+ LOC)
│   ├── dataflow.go          # Taint tracking & data flow analysis
│   ├── mcp.go               # MCP server implementation
│   ├── mcp_runtime.go       # NEW — 5 new MCP tool implementations
│   ├── autopentest.go       # Autonomous AI pentest engine
│   ├── livetest.go          # NEW — Live API key / URL probing engine
│   ├── evidence.go          # NEW — Evidence capture (screenshot, netcap, bundle)
│   ├── reproduce.go         # NEW — Frida-based finding reproduction engine
│   ├── sideload.go          # NEW — Non-JB device installer (libimobiledevice)
│   ├── ai.go                # AI integration (OpenAI-compatible)
│   ├── report.go            # Report generation (JSON/MD/HTML)
│   ├── frida.go             # Frida runtime instrumentation
│   └── ...
└── assets/                   # Frida scripts
    ├── ssl_bypass.js
    ├── crypto_monitor.js
    ├── auto_repro_network.js  # NEW — URLSession / CFURLRequest hooks
    ├── auto_repro_keychain.js # NEW — SecItem* hooks
    ├── auto_repro_storage.js  # NEW — NSUserDefaults / NSFileManager / fopen
    ├── auto_repro_crypto.js   # NEW — CCCrypt / MD5 / PBKDF hooks
    ├── auto_repro_url_scheme.js # NEW — AppDelegate / SceneDelegate openURL
    └── ...
```

## Command Reference

| Command | Description |
|---------|-------------|
| `ioshunt <bundle-id>` | Full pipeline (download → inject → resign → install → attach) |
| `ioshunt recon <bundle-id>` | Static analysis (26 phases) |
| `ioshunt analyze <bundle-id>` | AI vulnerability assessment |
| `ioshunt autopentest <bundle-id>` | AI autonomous pentest (agentic loop) |
| `ioshunt autohunt <bundle-id>` | **NEW** — Full pipeline: recon → live verify → repro → evidence |
| `ioshunt livetest <bundle-id>` | **NEW** — Probe findings live against real services |
| `ioshunt reproduce <bundle-id>` | **NEW** — Auto-reproduce findings on device via Frida hooks |
| `ioshunt sideload <subcommand>` | **NEW** — Non-JB device management (list/pair/install/uninstall/apps) |
| `ioshunt mcp` | Start MCP server for Claude Desktop |
| `ioshunt attach <process>` | Frida runtime attachment |
| `ioshunt dump <type> <bundle-id>` | Forensic data extraction |
| `ioshunt report <bundle-id>` | Generate formatted reports |
| `ioshunt download <bundle-id>` | Download IPA from App Store |
| `ioshunt config show\|set` | Manage configuration |
| `ioshunt doctor` | Environment health check |
| `ioshunt update` | Self-update |
| `ioshunt clean` | Clean workspace |

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
MIT
