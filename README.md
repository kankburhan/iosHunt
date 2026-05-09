# iOSHunt

**One Command iOS Pentesting Pipeline — Now with AI Auto-Pentest**

`ioshunt` is a comprehensive CLI tool designed to automate the entire lifecycle of an iOS application security assessment. From downloading the IPA to AI-driven autonomous pentesting, it handles everything so you can focus on finding vulnerabilities.

## Features (v1.13.0)

### 1. Automation Pipeline
-   **Download**: Fetches IPAs from the App Store (handles auth & country selection).
-   **Injection**: Automatically inserts `FridaGadget.dylib`.
-   **Resigning**: Resigns the app with your development profile.
-   **Installation**: Deploys to connected devices via `ios-deploy`.

### 2. Static Analysis (26-Phase Recon Engine)
-   **Secrets Scanning**: Detects hardcoded keys, tokens, and private data (12+ patterns with entropy analysis).
-   **Misconfigurations**: Checks `Info.plist` (ATS, File Sharing) and Entitlements (`get-task-allow`).
-   **Binary Security**: Verifies PIE, ARC, Stack Canaries, and Encryption status.
-   **Data Flow Analysis**: Taint tracking from sources (secrets) to sinks (logging, network, storage). 42K+ flows on real apps.
-   **Crypto Issues**: Weak algorithms, unsafe random generation, ECB mode detection.
-   **Code Injection**: SQL injection, XSS, format string, and deserialization vulnerabilities.
-   **Advanced Detectors**: Keychain API misuse, logging data leaks, entitlements misconfiguration, insecure network config.
-   **Reporting**: JSON, Markdown, and HTML reports with full taint graph visualization.

### 3. AI-Powered Analysis
-   **AI Assessment**: Sends reports to AI for deep vulnerability analysis and remediation.
-   **Multi-Provider**: Works with OpenAI (GPT-4o), Anthropic (Claude), Ollama, Groq, and any OpenAI-compatible API.
-   **OWASP MASVS Mapping**: Automated categorization of findings.

### 4. AI Auto-Pentest (NEW)
Fully autonomous AI-driven penetration testing. The AI agent orchestrates the entire assessment:

-   **MCP Server Mode**: Connect to Claude Desktop as an MCP tool server — Claude becomes your AI pentester.
-   **Standalone Mode**: Run `ioshunt autopentest` for a self-contained AI agent loop with tool-use.
-   **14 Tools**: The AI has access to recon, findings analysis, Frida script generation, exploit verification, reporting, and more.
-   **Agentic Loop**: AI decides what to analyze next, drills into findings, generates PoCs, and creates the final report.
-   **Multi-API Support**: Works with Claude API (native tool-use), GPT-4 (function calling), or any OpenAI-compatible endpoint.

### 5. Dynamic Analysis (Runtime)
-   **Frida Integration**: Attaches to running processes with auto device detection.
-   **Bypasses**: SSL Pinning, Biometrics, Jailbreak Detection, iXGuard/Anti-Debugging.
-   **Forensics**: Dumps Keychain, Cookies, and NSUserDefaults.
-   **Monitoring**: Real-time crypto operations, HTTP headers, URL scheme, NSCoding, and Keychain monitoring.
-   **Custom Scripts**: Plugin system for custom Frida scripts.

### 6. Utilities
-   **Doctor**: Verifies environment health and dependencies.
-   **Update**: Self-updating binary.
-   **Clean**: Workspace cleanup.
-   **Config**: Manage AI API credentials and settings.

## Installation

### Prerequisites
-   macOS (Required for `codesign`, `security`)
-   Go 1.24+
-   `frida`, `objection`, `ideviceinstaller`, `ios-deploy`

### Build from Source
```bash
git clone https://github.com/mburhan/ioshunt.git
cd ioshunt
go install
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

**Available MCP Tools (14):**
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
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go            # Main pipeline orchestrator
│   ├── recon.go           # Static analysis command
│   ├── analyze.go         # AI analysis command
│   ├── autopentest.go     # AI auto-pentest command (NEW)
│   ├── mcp.go             # MCP server command (NEW)
│   ├── attach.go          # Frida attachment
│   ├── dump.go            # Forensic extraction
│   └── ...
├── core/                   # Core modules
│   ├── recon.go           # 26-phase static analysis engine (1500+ LOC)
│   ├── dataflow.go        # Taint tracking & data flow analysis
│   ├── mcp.go             # MCP server implementation (NEW)
│   ├── autopentest.go     # Autonomous AI pentest engine (NEW)
│   ├── ai.go              # AI integration (OpenAI-compatible)
│   ├── report.go          # Report generation (JSON/MD/HTML)
│   ├── frida.go           # Frida runtime instrumentation
│   └── ...
└── assets/                 # Frida scripts
    ├── ssl_bypass.js
    ├── crypto_monitor.js
    └── ...
```

## Command Reference

| Command | Description |
|---------|-------------|
| `ioshunt <bundle-id>` | Full pipeline (download → inject → resign → install → attach) |
| `ioshunt recon <bundle-id>` | Static analysis (26 phases) |
| `ioshunt analyze <bundle-id>` | AI vulnerability assessment |
| `ioshunt autopentest <bundle-id>` | **AI autonomous pentest** |
| `ioshunt mcp` | **Start MCP server for Claude Desktop** |
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
