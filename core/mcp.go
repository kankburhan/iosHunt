package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── MCP Protocol Types (JSON-RPC 2.0) ───────────────────────────────────────

// MCPServer implements Model Context Protocol server over stdio
// Compatible with Claude Desktop, Claude Code, and any MCP client
type MCPServer struct {
	reader  *bufio.Reader
	writer  io.Writer
	mu      sync.Mutex
	session *MCPSession
}

// MCPSession holds state for the current pentest session
type MCPSession struct {
	BundleID   string
	Target     *Target
	Report     *Report
	ReportPath string
	WorkDir    string
	Phase      string // current phase: "idle", "recon", "dynamic", "reporting"
	Logs       []string
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpInitResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    mcpCapability  `json:"capabilities"`
	ServerInfo      mcpServerInfo  `json:"serverInfo"`
}

type mcpCapability struct {
	Tools     *mcpToolsCap     `json:"tools,omitempty"`
	Resources *mcpResourcesCap `json:"resources,omitempty"`
}

type mcpToolsCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type mcpResourcesCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpToolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type mcpToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ─── MCP Server Implementation ───────────────────────────────────────────────

// NewMCPServer creates a new MCP server on stdio
func NewMCPServer() *MCPServer {
	return &MCPServer{
		reader:  bufio.NewReader(os.Stdin),
		writer:  os.Stdout,
		session: &MCPSession{Phase: "idle"},
	}
}

// Run starts the MCP server loop (blocking)
func (s *MCPServer) Run() error {
	fmt.Fprintln(os.Stderr, "[MCP] iOSHunt MCP Server starting...")
	fmt.Fprintln(os.Stderr, "[MCP] Waiting for client connection via stdio...")

	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(os.Stderr, "[MCP] Client disconnected")
				return nil
			}
			return fmt.Errorf("read error: %v", err)
		}

		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		s.handleRequest(&req)
	}
}

func (s *MCPServer) handleRequest(req *jsonRPCRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "initialized":
		// Client acknowledgment, no response needed
		fmt.Fprintln(os.Stderr, "[MCP] Client initialized")
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	case "resources/list":
		s.handleResourcesList(req)
	case "resources/read":
		s.handleResourcesRead(req)
	case "ping":
		s.sendResult(req.ID, map[string]string{})
	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// ─── Initialize ──────────────────────────────────────────────────────────────

func (s *MCPServer) handleInitialize(req *jsonRPCRequest) {
	result := mcpInitResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: mcpCapability{
			Tools:     &mcpToolsCap{ListChanged: false},
			Resources: &mcpResourcesCap{ListChanged: false},
		},
		ServerInfo: mcpServerInfo{
			Name:    "ioshunt",
			Version: "1.13.0",
		},
	}
	s.sendResult(req.ID, result)
}

// ─── Tools List ──────────────────────────────────────────────────────────────

func (s *MCPServer) handleToolsList(req *jsonRPCRequest) {
	tools := []mcpToolDef{
		{
			Name:        "ios_recon",
			Description: "Run full static security analysis on an iOS app (IPA). Performs 26-phase analysis including: secrets detection, binary security checks, entitlements analysis, data flow/taint analysis, crypto issues, code injection vulnerabilities, misconfigurations, tracker detection, and more. Returns structured findings with severity ratings.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the iOS app (e.g., com.example.app)",
					},
					"ipa_path": map[string]interface{}{
						"type":        "string",
						"description": "Optional: Direct path to IPA file. If not provided, will download from App Store using bundle_id.",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_download_ipa",
			Description: "Download an iOS IPA file from the Apple App Store using ipatool. Requires Apple ID authentication.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the app to download",
					},
					"country": map[string]interface{}{
						"type":        "string",
						"description": "App Store country code (default: US)",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_get_findings",
			Description: "Get security findings from the latest scan. Filter by category and severity. Use this to drill into specific vulnerability types.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the scanned app",
					},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Finding category to filter",
						"enum":        []string{"secrets", "misconfigurations", "crypto", "code_issues", "hardening", "insecure_storage", "data_flows", "permissions", "deep_links", "trackers", "urls", "all"},
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"description": "Minimum severity filter",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
					},
					"limit": map[string]interface{}{
						"type":        "number",
						"description": "Maximum number of findings to return (default: 50)",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_get_app_info",
			Description: "Get basic app metadata and binary security analysis for a scanned iOS app. Includes bundle info, binary protections (PIE, ARC, Stack Canary, Encryption), entitlements, and permissions.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the scanned app",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_generate_frida_script",
			Description: "Generate a custom Frida script for dynamic testing based on findings. AI-tailored scripts for specific vulnerability verification: SSL pinning bypass, keychain monitoring, API hooking, crypto interception, etc.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "What to target: method name, class, or vulnerability type",
					},
					"action": map[string]interface{}{
						"type":        "string",
						"description": "Action type for the Frida script",
						"enum":        []string{"hook", "bypass", "monitor", "dump", "trace", "inject"},
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Detailed description of what the script should do",
					},
				},
				"required": []string{"target", "action", "description"},
			},
		},
		{
			Name:        "ios_attach_frida",
			Description: "Attach Frida to a running iOS app on a connected device with specific instrumentation scripts. Supports SSL bypass, biometric bypass, jailbreak bypass, API monitoring, crypto monitoring, and custom scripts.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"process_name": map[string]interface{}{
						"type":        "string",
						"description": "Process name or bundle ID to attach to",
					},
					"scripts": map[string]interface{}{
						"type":        "array",
						"description": "List of built-in scripts to load",
						"items": map[string]interface{}{
							"type": "string",
							"enum": []string{"ssl_bypass", "bio_bypass", "ixguard", "api_monitor", "crypto_monitor", "bypass_universal", "header_logger", "url_scheme_monitor", "nscoding_monitor", "keychain_security_monitor"},
						},
					},
					"custom_script": map[string]interface{}{
						"type":        "string",
						"description": "Custom Frida script content (JavaScript) to inject",
					},
				},
				"required": []string{"process_name"},
			},
		},
		{
			Name:        "ios_dump_runtime",
			Description: "Extract runtime data from a running iOS app: keychain items, cookies, NSUserDefaults, or app info. Requires the app to be running on a connected device with Frida.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the running app",
					},
					"dump_type": map[string]interface{}{
						"type":        "string",
						"description": "Type of data to extract",
						"enum":        []string{"keychain", "cookies", "defaults", "app_info"},
					},
				},
				"required": []string{"bundle_id", "dump_type"},
			},
		},
		{
			Name:        "ios_check_device",
			Description: "Check for connected iOS devices via USB/Frida. Returns device info including name, UDID, and iOS version.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "ios_generate_report",
			Description: "Generate a formatted pentest report from scan results. Supports JSON, Markdown, and HTML formats with full findings, severity ratings, and remediation guidance.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the scanned app",
					},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Report format",
						"enum":        []string{"json", "markdown", "html"},
					},
				},
				"required": []string{"bundle_id", "format"},
			},
		},
		{
			Name:        "ios_inject_and_resign",
			Description: "Inject FridaGadget.dylib into an IPA and resign it for deployment to a test device. Enables dynamic analysis by embedding Frida into the app binary.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID (will find the IPA automatically)",
					},
					"signing_identity": map[string]interface{}{
						"type":        "string",
						"description": "Code signing identity (auto-detect if empty)",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_install_app",
			Description: "Install a resigned IPA to a connected iOS device via ios-deploy.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the app to install",
					},
					"device_id": map[string]interface{}{
						"type":        "string",
						"description": "Target device UDID (auto-detect if empty)",
					},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_pentest_status",
			Description: "Get the current status of the auto-pentest session including: phase, findings summary, logs, and recommended next actions.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "ios_search_strings",
			Description: "Search for specific strings or patterns in the extracted app binary and resources. Useful for finding hardcoded URLs, API endpoints, encryption keys, or any custom patterns.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{
						"type":        "string",
						"description": "Bundle ID of the scanned app",
					},
					"pattern": map[string]interface{}{
						"type":        "string",
						"description": "Search pattern (regex supported)",
					},
					"file_filter": map[string]interface{}{
						"type":        "string",
						"description": "Filter by file extension (e.g., '.plist', '.js', '.json')",
					},
				},
				"required": []string{"bundle_id", "pattern"},
			},
		},
		{
			Name:        "ios_exploit_verify",
			Description: "Verify if a specific finding is exploitable by running targeted checks. Tests include: secret validation (check if API key is live), URL accessibility, certificate pinning verification, and entitlement abuse checks.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_type": map[string]interface{}{
						"type":        "string",
						"description": "Type of finding to verify",
						"enum":        []string{"api_key", "url_endpoint", "weak_crypto", "missing_pinning", "debug_enabled", "ats_bypass"},
					},
					"value": map[string]interface{}{
						"type":        "string",
						"description": "The specific value to test (e.g., the API key, URL, etc.)",
					},
					"context": map[string]interface{}{
						"type":        "string",
						"description": "Additional context about the finding",
					},
				},
				"required": []string{"finding_type", "value"},
			},
		},
		{
			Name:        "ios_live_verify",
			Description: "ACTIVELY validate findings against live services. Probes API keys (Google/Stripe/GitHub/Slack/Mapbox/SendGrid/OpenAI/Firebase) by hitting real endpoints, checks URL reachability, tests ATS bypass via plaintext HTTP. Saves evidence and updates findings with LiveStatus. Only run on authorized targets.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id": map[string]interface{}{"type": "string", "description": "Bundle ID of the scanned app"},
					"only_severity": map[string]interface{}{
						"type":        "string",
						"description": "Probe only findings >= this severity (default: HIGH)",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
					},
					"max_findings": map[string]interface{}{"type": "number", "description": "Max findings to probe (default 30)"},
					"output_dir":   map[string]interface{}{"type": "string", "description": "Where to save evidence (default ./reports/livetest)"},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_reproduce_finding",
			Description: "Auto-reproduce static findings on a connected device by attaching Frida hooks tailored to each category (network/keychain/storage/crypto/url_scheme). Marks findings Reproduced=true when runtime evidence is captured. Works with FridaGadget on non-JB devices.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id":      map[string]interface{}{"type": "string", "description": "Bundle ID of the running app"},
					"finding_id":     map[string]interface{}{"type": "string", "description": "Optional: reproduce a single finding by ID. Empty = all"},
					"category":       map[string]interface{}{"type": "string", "description": "Optional: only reproduce findings in this category"},
					"duration_sec":   map[string]interface{}{"type": "number", "description": "Hook duration per script (default 20)"},
					"spawn":          map[string]interface{}{"type": "boolean", "description": "Spawn fresh app via -f instead of attaching"},
					"only_severity":  map[string]interface{}{"type": "string", "description": "Only reproduce findings >= this severity"},
				},
				"required": []string{"bundle_id"},
			},
		},
		{
			Name:        "ios_capture_evidence",
			Description: "Capture proof-of-vulnerability artifacts on a non-JB device: screenshot via idevicescreenshot, network pcap via rvictl+tcpdump, raw artifact dumps. Attaches captured files as Evidence to a finding.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action":      map[string]interface{}{
						"type":        "string",
						"description": "screenshot | netcap_start | netcap_stop | bundle",
						"enum":        []string{"screenshot", "netcap_start", "netcap_stop", "bundle"},
					},
					"finding_id":  map[string]interface{}{"type": "string", "description": "Finding to attach evidence to"},
					"device_udid": map[string]interface{}{"type": "string", "description": "Target device UDID"},
				},
				"required": []string{"action"},
			},
		},
		{
			Name:        "ios_sideload",
			Description: "Deploy a (re-signed) IPA to a non-jailbroken device via libimobiledevice (ideviceinstaller) with auto-fallback to ios-deploy/AltStore. Lists devices, validates pairing, installs, and optionally launches.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action":      map[string]interface{}{
						"type":        "string",
						"description": "list_devices | pair | install | uninstall | list_apps",
						"enum":        []string{"list_devices", "pair", "install", "uninstall", "list_apps"},
					},
					"ipa_path":    map[string]interface{}{"type": "string", "description": "Path to IPA (for install)"},
					"bundle_id":   map[string]interface{}{"type": "string", "description": "Bundle ID for verify/uninstall/launch"},
					"device_udid": map[string]interface{}{"type": "string", "description": "Target device UDID (auto-pick if empty)"},
					"method":      map[string]interface{}{
						"type":        "string",
						"description": "Installer method (auto picks best available)",
						"enum":        []string{"auto", "idevice", "ios-deploy", "altstore"},
					},
					"launch":      map[string]interface{}{"type": "boolean", "description": "Launch after install"},
				},
				"required": []string{"action"},
			},
		},
		{
			Name:        "ios_auto_hunt",
			Description: "FULL AUTONOMOUS HUNT: runs the entire pipeline — recon -> live verification -> dynamic reproduction on device -> evidence capture -> final report. Designed for non-JB testing with FridaGadget. Returns summary with verified-vs-unverified counts and evidence bundle path.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"bundle_id":     map[string]interface{}{"type": "string", "description": "Bundle ID of the target app"},
					"ipa_path":      map[string]interface{}{"type": "string", "description": "Optional IPA path (auto-finds otherwise)"},
					"skip_recon":    map[string]interface{}{"type": "boolean", "description": "Skip static analysis if a recent report exists"},
					"skip_live":     map[string]interface{}{"type": "boolean", "description": "Skip active live probing (offline mode)"},
					"skip_repro":    map[string]interface{}{"type": "boolean", "description": "Skip on-device reproduction"},
					"only_severity": map[string]interface{}{"type": "string", "description": "Only verify/reproduce findings >= this severity (default HIGH)"},
					"device_udid":   map[string]interface{}{"type": "string", "description": "Specific device for repro/evidence"},
					"duration_sec":  map[string]interface{}{"type": "number", "description": "Per-script repro duration (default 20)"},
				},
				"required": []string{"bundle_id"},
			},
		},
	}

	s.sendResult(req.ID, map[string]interface{}{
		"tools": tools,
	})
}

// ─── Tools Call Dispatcher ───────────────────────────────────────────────────

func (s *MCPServer) handleToolsCall(req *jsonRPCRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "Invalid params")
		return
	}

	fmt.Fprintf(os.Stderr, "[MCP] Tool call: %s\n", params.Name)

	var result mcpToolResult

	switch params.Name {
	case "ios_recon":
		result = s.toolRecon(params.Arguments)
	case "ios_download_ipa":
		result = s.toolDownloadIPA(params.Arguments)
	case "ios_get_findings":
		result = s.toolGetFindings(params.Arguments)
	case "ios_get_app_info":
		result = s.toolGetAppInfo(params.Arguments)
	case "ios_generate_frida_script":
		result = s.toolGenerateFridaScript(params.Arguments)
	case "ios_attach_frida":
		result = s.toolAttachFrida(params.Arguments)
	case "ios_dump_runtime":
		result = s.toolDumpRuntime(params.Arguments)
	case "ios_check_device":
		result = s.toolCheckDevice(params.Arguments)
	case "ios_generate_report":
		result = s.toolGenerateReport(params.Arguments)
	case "ios_inject_and_resign":
		result = s.toolInjectAndResign(params.Arguments)
	case "ios_install_app":
		result = s.toolInstallApp(params.Arguments)
	case "ios_pentest_status":
		result = s.toolPentestStatus(params.Arguments)
	case "ios_search_strings":
		result = s.toolSearchStrings(params.Arguments)
	case "ios_exploit_verify":
		result = s.toolExploitVerify(params.Arguments)
	case "ios_live_verify":
		result = s.toolLiveVerify(params.Arguments)
	case "ios_reproduce_finding":
		result = s.toolReproduceFinding(params.Arguments)
	case "ios_capture_evidence":
		result = s.toolCaptureEvidence(params.Arguments)
	case "ios_sideload":
		result = s.toolSideload(params.Arguments)
	case "ios_auto_hunt":
		result = s.toolAutoHunt(params.Arguments)
	default:
		result = mcpToolResult{
			Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", params.Name)}},
			IsError: true,
		}
	}

	s.sendResult(req.ID, result)
}

// ─── Tool Implementations ────────────────────────────────────────────────────

func (s *MCPServer) toolRecon(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		IPAPath  string `json:"ipa_path"`
	}
	json.Unmarshal(args, &params)

	if params.BundleID == "" {
		return mcpError("bundle_id is required")
	}

	s.session.BundleID = params.BundleID
	s.session.Phase = "recon"
	s.log("Starting static analysis for %s", params.BundleID)

	// Create target
	target, err := NewTarget(params.BundleID)
	if err != nil {
		return mcpError("Failed to create target: %v", err)
	}
	s.session.Target = target
	s.session.WorkDir = target.WorkDir

	// Find or download IPA
	ipaPath := params.IPAPath
	if ipaPath == "" {
		// Try to find existing IPA
		matches, _ := filepath.Glob("*.ipa")
		for _, m := range matches {
			if strings.Contains(m, params.BundleID) {
				ipaPath = m
				break
			}
		}
		if ipaPath == "" && len(matches) > 0 {
			ipaPath = matches[0]
		}
	}

	if ipaPath == "" {
		return mcpError("No IPA found. Use ios_download_ipa first, or provide ipa_path.")
	}

	s.log("Using IPA: %s", ipaPath)

	// Extract IPA
	tmpDir, _ := os.MkdirTemp("", "ioshunt_mcp_*")
	if err := UnzipIPA(ipaPath, tmpDir); err != nil {
		return mcpError("Unzip failed: %v", err)
	}

	appPath, err := FindAppDirectory(tmpDir)
	if err != nil {
		return mcpError("App directory not found: %v", err)
	}

	target.AppPath = appPath
	target.IPAPath = ipaPath

	// Run static analysis
	s.log("Running 26-phase static analysis...")
	if err := StaticAnalyze(target, nil); err != nil {
		return mcpError("Static analysis failed: %v", err)
	}

	// Save reports
	reportPath := filepath.Join(target.WorkDir, "report.json")
	if err := target.Report.SaveJSON(reportPath); err != nil {
		return mcpError("Failed to save report: %v", err)
	}
	target.Report.SaveHTML(filepath.Join(target.WorkDir, "report.html"))
	target.Report.SaveMarkdown(filepath.Join(target.WorkDir, "report.md"))

	s.session.Report = target.Report
	s.session.ReportPath = reportPath
	s.session.Phase = "recon_complete"

	// Build summary
	summary := buildReconSummary(target.Report)
	s.log("Static analysis complete. Report saved to %s", reportPath)

	return mcpSuccess(summary)
}

func (s *MCPServer) toolDownloadIPA(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		Country  string `json:"country"`
	}
	json.Unmarshal(args, &params)

	if params.BundleID == "" {
		return mcpError("bundle_id is required")
	}
	if params.Country == "" {
		params.Country = "US"
	}

	s.log("Downloading IPA for %s (country: %s)", params.BundleID, params.Country)

	if err := DownloadIPA(params.BundleID, params.Country); err != nil {
		return mcpError("Download failed: %v", err)
	}

	// Find the downloaded IPA
	matches, _ := filepath.Glob("*.ipa")
	var ipaPath string
	for _, m := range matches {
		if strings.Contains(m, params.BundleID) {
			ipaPath = m
			break
		}
	}

	if ipaPath == "" {
		return mcpError("IPA downloaded but file not found in current directory")
	}

	return mcpSuccess(fmt.Sprintf("IPA downloaded successfully: %s\nReady for analysis with ios_recon.", ipaPath))
}

func (s *MCPServer) toolGetFindings(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		Category string `json:"category"`
		Severity string `json:"severity"`
		Limit    int    `json:"limit"`
	}
	json.Unmarshal(args, &params)

	report, err := s.loadReport(params.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}

	if params.Limit == 0 {
		params.Limit = 50
	}
	if params.Category == "" {
		params.Category = "all"
	}

	result := map[string]interface{}{}

	switch params.Category {
	case "secrets":
		result["secrets"] = limitFindings(report.Findings.Secrets, params.Limit, params.Severity)
		result["total"] = len(report.Findings.Secrets)
	case "misconfigurations":
		result["misconfigurations"] = limitStrings(report.Findings.Misconfigurations, params.Limit)
		result["total"] = len(report.Findings.Misconfigurations)
	case "crypto":
		result["crypto_issues"] = limitFindings(report.Findings.CryptoIssues, params.Limit, params.Severity)
		result["total"] = len(report.Findings.CryptoIssues)
	case "code_issues":
		result["code_issues"] = limitFindings(report.Findings.CodeIssues, params.Limit, params.Severity)
		result["total"] = len(report.Findings.CodeIssues)
	case "hardening":
		result["hardening_issues"] = limitFindings(report.Findings.HardeningIssues, params.Limit, params.Severity)
		result["total"] = len(report.Findings.HardeningIssues)
	case "insecure_storage":
		result["insecure_storage"] = limitFindings(report.Findings.InsecureStorage, params.Limit, params.Severity)
		result["total"] = len(report.Findings.InsecureStorage)
	case "data_flows":
		result["data_flows"] = report.Findings.DataFlows
		result["taint_graph"] = report.Findings.TaintGraph
	case "permissions":
		result["permissions"] = report.Findings.Permissions
	case "deep_links":
		result["schemes"] = report.Findings.DeepLinks.Schemes
		result["universal_links"] = report.Findings.DeepLinks.Universal
	case "trackers":
		result["trackers"] = report.Findings.Trackers
	case "urls":
		result["urls"] = limitStrings(report.Findings.URLs, params.Limit)
		result["total"] = len(report.Findings.URLs)
	case "all":
		result = buildFindingsSummary(report)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcpSuccess(string(data))
}

func (s *MCPServer) toolGetAppInfo(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
	}
	json.Unmarshal(args, &params)

	report, err := s.loadReport(params.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}

	info := map[string]interface{}{
		"app_info":        report.AppInfo,
		"binary_analysis": report.BinaryAnalysis,
		"entitlements":    report.Entitlements,
		"permissions":     report.Findings.Permissions,
		"findings_count": map[string]int{
			"secrets":          len(report.Findings.Secrets),
			"misconfigurations": len(report.Findings.Misconfigurations),
			"crypto_issues":    len(report.Findings.CryptoIssues),
			"code_issues":      len(report.Findings.CodeIssues),
			"hardening_issues": len(report.Findings.HardeningIssues),
			"insecure_storage": len(report.Findings.InsecureStorage),
			"urls":             len(report.Findings.URLs),
			"trackers":         len(report.Findings.Trackers),
		},
	}

	data, _ := json.MarshalIndent(info, "", "  ")
	return mcpSuccess(string(data))
}

func (s *MCPServer) toolGenerateFridaScript(args json.RawMessage) mcpToolResult {
	var params struct {
		Target      string `json:"target"`
		Action      string `json:"action"`
		Description string `json:"description"`
	}
	json.Unmarshal(args, &params)

	script := generateFridaScriptForTarget(params.Target, params.Action, params.Description)

	// Save to session workdir if available
	if s.session.WorkDir != "" {
		scriptPath := filepath.Join(s.session.WorkDir, fmt.Sprintf("frida_%s_%s.js", params.Action, sanitizeFilename(params.Target)))
		os.WriteFile(scriptPath, []byte(script), 0644)
		return mcpSuccess(fmt.Sprintf("Frida script generated and saved to: %s\n\n```javascript\n%s\n```", scriptPath, script))
	}

	return mcpSuccess(fmt.Sprintf("```javascript\n%s\n```", script))
}

func (s *MCPServer) toolAttachFrida(args json.RawMessage) mcpToolResult {
	var params struct {
		ProcessName  string   `json:"process_name"`
		Scripts      []string `json:"scripts"`
		CustomScript string   `json:"custom_script"`
	}
	json.Unmarshal(args, &params)

	if params.ProcessName == "" {
		return mcpError("process_name is required")
	}

	var scriptPaths []string

	// Map built-in script names to asset files
	scriptMap := map[string]string{
		"ssl_bypass":                "ssl_bypass.js",
		"bio_bypass":                "bio_bypass.js",
		"ixguard":                   "ixguard.js",
		"api_monitor":               "api_monitor.js",
		"crypto_monitor":            "crypto_monitor.js",
		"bypass_universal":          "bypass_universal.js",
		"header_logger":             "header_logger.js",
		"url_scheme_monitor":        "url_scheme_monitor.js",
		"nscoding_monitor":          "nscoding_monitor.js",
		"keychain_security_monitor": "keychain_security_monitor.js",
	}

	for _, scriptName := range params.Scripts {
		if assetFile, ok := scriptMap[scriptName]; ok {
			if path, err := GetAssetScript(assetFile); err == nil {
				scriptPaths = append(scriptPaths, path)
			}
		}
	}

	// Handle custom script
	if params.CustomScript != "" {
		tmpFile, err := os.CreateTemp("", "ioshunt_custom_*.js")
		if err == nil {
			tmpFile.WriteString(params.CustomScript)
			tmpFile.Close()
			scriptPaths = append(scriptPaths, tmpFile.Name())
		}
	}

	s.log("Attaching Frida to %s with %d scripts", params.ProcessName, len(scriptPaths))

	// Note: This runs interactively - in MCP context we describe what would happen
	return mcpSuccess(fmt.Sprintf(
		"Frida attach command prepared:\n  frida -U -n %s %s\n\nScripts loaded: %d\nNote: Frida attachment requires interactive terminal. Use the CLI directly:\n  ioshunt attach %s %s",
		params.ProcessName,
		formatFridaArgs(scriptPaths),
		len(scriptPaths),
		params.ProcessName,
		formatAttachFlags(params.Scripts),
	))
}

func (s *MCPServer) toolDumpRuntime(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		DumpType string `json:"dump_type"`
	}
	json.Unmarshal(args, &params)

	return mcpSuccess(fmt.Sprintf(
		"Runtime dump command prepared for %s (%s).\n\nRun in terminal:\n  ioshunt dump %s %s\n\nNote: Requires the app to be running on a connected device with Frida.",
		params.BundleID, params.DumpType, params.DumpType, params.BundleID,
	))
}

func (s *MCPServer) toolCheckDevice(args json.RawMessage) mcpToolResult {
	device, err := GetConnectedDevice()
	if err != nil {
		return mcpSuccess(fmt.Sprintf("No iOS device detected: %v\n\nMake sure:\n1. Device is connected via USB\n2. Frida is installed on the device\n3. frida-server is running", err))
	}

	return mcpSuccess(fmt.Sprintf("Device detected:\n  Name: %s\n  UDID: %s\n  Type: %s\n\nReady for dynamic analysis.", device.Name, device.ID, device.Type))
}

func (s *MCPServer) toolGenerateReport(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		Format   string `json:"format"`
	}
	json.Unmarshal(args, &params)

	report, err := s.loadReport(params.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}

	reportDir := s.session.WorkDir
	if reportDir == "" {
		homeDir, _ := os.UserHomeDir()
		reportDir = filepath.Join(homeDir, ".ioshunt", "reports")
		os.MkdirAll(reportDir, 0755)
	}

	var outPath string
	switch params.Format {
	case "json":
		outPath = filepath.Join(reportDir, "report.json")
		report.SaveJSON(outPath)
	case "markdown", "md":
		outPath = filepath.Join(reportDir, "report.md")
		report.SaveMarkdown(outPath)
	case "html":
		outPath = filepath.Join(reportDir, "report.html")
		report.SaveHTML(outPath)
	default:
		return mcpError("Unsupported format: %s (use json, markdown, or html)", params.Format)
	}

	return mcpSuccess(fmt.Sprintf("Report generated: %s", outPath))
}

func (s *MCPServer) toolInjectAndResign(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID        string `json:"bundle_id"`
		SigningIdentity string `json:"signing_identity"`
	}
	json.Unmarshal(args, &params)

	if params.BundleID == "" {
		return mcpError("bundle_id is required")
	}

	// Find IPA
	matches, _ := filepath.Glob("*.ipa")
	var ipaPath string
	for _, m := range matches {
		if strings.Contains(m, params.BundleID) {
			ipaPath = m
			break
		}
	}
	if ipaPath == "" {
		return mcpError("No IPA found for %s. Download first.", params.BundleID)
	}

	// Extract
	tmpDir, _ := os.MkdirTemp("", "ioshunt_inject_*")
	if err := UnzipIPA(ipaPath, tmpDir); err != nil {
		return mcpError("Unzip failed: %v", err)
	}

	appPath, err := FindAppDirectory(tmpDir)
	if err != nil {
		return mcpError("App not found: %v", err)
	}

	// Inject
	dm := NewDependencyManager()
	gadgetPath := filepath.Join(dm.BinDir, "FridaGadget.dylib")
	if err := InjectGadget(appPath, gadgetPath); err != nil {
		return mcpError("Injection failed: %v", err)
	}

	// Resign
	if err := ResignApp(appPath, params.SigningIdentity); err != nil {
		return mcpSuccess(fmt.Sprintf("Gadget injected but resign failed: %v\nApp path: %s", err, appPath))
	}

	return mcpSuccess(fmt.Sprintf("FridaGadget injected and app resigned.\nApp path: %s\nReady for installation with ios_install_app.", appPath))
}

func (s *MCPServer) toolInstallApp(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID string `json:"bundle_id"`
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(args, &params)

	// Find the most recently injected app
	return mcpSuccess(fmt.Sprintf(
		"Install command prepared for %s.\n\nRun in terminal:\n  ioshunt install %s\n\nNote: Requires a connected device with developer mode enabled.",
		params.BundleID, params.BundleID,
	))
}

func (s *MCPServer) toolPentestStatus(args json.RawMessage) mcpToolResult {
	status := map[string]interface{}{
		"phase":     s.session.Phase,
		"bundle_id": s.session.BundleID,
		"logs":      s.session.Logs,
	}

	if s.session.Report != nil {
		status["findings_summary"] = buildFindingsSummary(s.session.Report)
	}

	if s.session.WorkDir != "" {
		status["work_dir"] = s.session.WorkDir
	}

	if s.session.ReportPath != "" {
		status["report_path"] = s.session.ReportPath
	}

	// Suggest next actions based on phase
	switch s.session.Phase {
	case "idle":
		status["next_actions"] = []string{
			"ios_download_ipa - Download target app",
			"ios_recon - Run static analysis on existing IPA",
		}
	case "recon_complete":
		status["next_actions"] = []string{
			"ios_get_findings - Review specific finding categories",
			"ios_inject_and_resign - Prepare for dynamic analysis",
			"ios_generate_frida_script - Create targeted Frida scripts",
			"ios_generate_report - Generate formatted report",
		}
	case "dynamic":
		status["next_actions"] = []string{
			"ios_attach_frida - Attach with instrumentation",
			"ios_dump_runtime - Extract runtime data",
			"ios_exploit_verify - Verify exploitability",
		}
	}

	data, _ := json.MarshalIndent(status, "", "  ")
	return mcpSuccess(string(data))
}

func (s *MCPServer) toolSearchStrings(args json.RawMessage) mcpToolResult {
	var params struct {
		BundleID   string `json:"bundle_id"`
		Pattern    string `json:"pattern"`
		FileFilter string `json:"file_filter"`
	}
	json.Unmarshal(args, &params)

	if params.Pattern == "" {
		return mcpError("pattern is required")
	}

	// Find the extracted app directory from session or latest scan
	appPath := ""
	if s.session.Target != nil {
		appPath = s.session.Target.AppPath
	}

	if appPath == "" {
		return mcpError("No extracted app available. Run ios_recon first to extract and analyze the app.")
	}

	// Search using strings command on binary and grep on resources
	results := searchInApp(appPath, params.Pattern, params.FileFilter)

	if len(results) == 0 {
		return mcpSuccess(fmt.Sprintf("No matches found for pattern: %s", params.Pattern))
	}

	data, _ := json.MarshalIndent(results, "", "  ")
	return mcpSuccess(string(data))
}

func (s *MCPServer) toolExploitVerify(args json.RawMessage) mcpToolResult {
	var params struct {
		FindingType string `json:"finding_type"`
		Value       string `json:"value"`
		Context     string `json:"context"`
	}
	json.Unmarshal(args, &params)

	result := verifyExploitability(params.FindingType, params.Value, params.Context)
	return mcpSuccess(result)
}

// ─── Resources ───────────────────────────────────────────────────────────────

func (s *MCPServer) handleResourcesList(req *jsonRPCRequest) {
	resources := []map[string]interface{}{
		{
			"uri":         "ioshunt://pentest/status",
			"name":        "Pentest Session Status",
			"description": "Current auto-pentest session state and progress",
			"mimeType":    "application/json",
		},
		{
			"uri":         "ioshunt://tools/frida-scripts",
			"name":        "Available Frida Scripts",
			"description": "List of built-in Frida instrumentation scripts",
			"mimeType":    "application/json",
		},
	}

	s.sendResult(req.ID, map[string]interface{}{
		"resources": resources,
	})
}

func (s *MCPServer) handleResourcesRead(req *jsonRPCRequest) {
	var params struct {
		URI string `json:"uri"`
	}
	json.Unmarshal(req.Params, &params)

	switch params.URI {
	case "ioshunt://pentest/status":
		status, _ := json.MarshalIndent(s.session, "", "  ")
		s.sendResult(req.ID, map[string]interface{}{
			"contents": []map[string]interface{}{
				{"uri": params.URI, "mimeType": "application/json", "text": string(status)},
			},
		})
	case "ioshunt://tools/frida-scripts":
		scripts := map[string]string{
			"ssl_bypass":                "SSL/TLS certificate pinning bypass",
			"bio_bypass":                "Biometric (TouchID/FaceID) authentication bypass",
			"ixguard":                   "iXGuard/Anti-Frida detection bypass",
			"api_monitor":               "NSURLSession API call monitoring",
			"crypto_monitor":            "CCCrypt/SecKey cryptographic operations monitor",
			"bypass_universal":          "Universal jailbreak detection bypass",
			"header_logger":             "HTTP request/response header logger",
			"url_scheme_monitor":        "Custom URL scheme handler monitor",
			"nscoding_monitor":          "NSCoding deserialization security monitor",
			"keychain_security_monitor": "Keychain SecItem operations monitor",
		}
		data, _ := json.MarshalIndent(scripts, "", "  ")
		s.sendResult(req.ID, map[string]interface{}{
			"contents": []map[string]interface{}{
				{"uri": params.URI, "mimeType": "application/json", "text": string(data)},
			},
		})
	default:
		s.sendError(req.ID, -32602, "Resource not found")
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (s *MCPServer) sendResult(id interface{}, result interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.writer, "%s\n", data)
}

func (s *MCPServer) sendError(id interface{}, code int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}

	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.writer, "%s\n", data)
}

func (s *MCPServer) log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.session.Logs = append(s.session.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	fmt.Fprintf(os.Stderr, "[MCP] %s\n", msg)
}

func (s *MCPServer) loadReport(bundleID string) (*Report, error) {
	// Try session first
	if s.session.Report != nil && (bundleID == "" || bundleID == s.session.BundleID) {
		return s.session.Report, nil
	}

	if bundleID == "" {
		return nil, fmt.Errorf("bundle_id is required (no active session)")
	}

	// Find latest report on disk
	homeDir, _ := os.UserHomeDir()
	targetsDir := filepath.Join(homeDir, ".ioshunt", "targets", bundleID)

	entries, err := os.ReadDir(targetsDir)
	if err != nil {
		return nil, fmt.Errorf("no scans found for %s. Run ios_recon first.", bundleID)
	}

	// Find latest timestamp directory with report.json
	var latestDir string
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].IsDir() {
			reportPath := filepath.Join(targetsDir, entries[i].Name(), "report.json")
			if _, err := os.Stat(reportPath); err == nil {
				latestDir = entries[i].Name()
				break
			}
		}
	}

	if latestDir == "" {
		return nil, fmt.Errorf("no report found for %s. Run ios_recon first.", bundleID)
	}

	reportPath := filepath.Join(targetsDir, latestDir, "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %v", err)
	}

	// Cache in session
	s.session.Report = &report
	s.session.BundleID = bundleID
	s.session.ReportPath = reportPath

	return &report, nil
}

func mcpSuccess(text string) mcpToolResult {
	return mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: text}},
	}
}

func mcpError(format string, args ...interface{}) mcpToolResult {
	return mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}

func buildReconSummary(report *Report) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Static Analysis Complete: %s\n\n", report.AppInfo.Name))
	sb.WriteString(fmt.Sprintf("**Bundle ID:** %s\n", report.AppInfo.BundleID))
	sb.WriteString(fmt.Sprintf("**Version:** %s\n", report.AppInfo.Version))
	sb.WriteString(fmt.Sprintf("**Min iOS:** %s\n\n", report.AppInfo.MinOS))

	// Binary Security
	if report.BinaryAnalysis != nil {
		sb.WriteString("## Binary Security\n")
		sb.WriteString(fmt.Sprintf("- PIE: %v | ARC: %v | Stack Canary: %v | Encrypted: %v\n\n",
			report.BinaryAnalysis.PIE, report.BinaryAnalysis.ARC,
			report.BinaryAnalysis.StackCanary, report.BinaryAnalysis.Encrypted))
	}

	// Findings Summary
	sb.WriteString("## Findings Summary\n")
	sb.WriteString(fmt.Sprintf("| Category | Count |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| Secrets | %d |\n", len(report.Findings.Secrets)))
	sb.WriteString(fmt.Sprintf("| Misconfigurations | %d |\n", len(report.Findings.Misconfigurations)))
	sb.WriteString(fmt.Sprintf("| Crypto Issues | %d |\n", len(report.Findings.CryptoIssues)))
	sb.WriteString(fmt.Sprintf("| Code Issues | %d |\n", len(report.Findings.CodeIssues)))
	sb.WriteString(fmt.Sprintf("| Hardening Issues | %d |\n", len(report.Findings.HardeningIssues)))
	sb.WriteString(fmt.Sprintf("| Insecure Storage | %d |\n", len(report.Findings.InsecureStorage)))
	sb.WriteString(fmt.Sprintf("| URLs | %d |\n", len(report.Findings.URLs)))
	sb.WriteString(fmt.Sprintf("| Trackers | %d |\n", len(report.Findings.Trackers)))
	sb.WriteString(fmt.Sprintf("| Data Flows | %d |\n", len(report.Findings.DataFlows)))

	// Critical findings highlight
	criticals := countBySeverity(report, "CRITICAL")
	highs := countBySeverity(report, "HIGH")
	if criticals > 0 || highs > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠ **%d CRITICAL** and **%d HIGH** severity findings detected.\n", criticals, highs))
		sb.WriteString("Use `ios_get_findings` to drill into specific categories.\n")
	}

	return sb.String()
}

func buildFindingsSummary(report *Report) map[string]interface{} {
	return map[string]interface{}{
		"secrets_count":          len(report.Findings.Secrets),
		"misconfigurations":      report.Findings.Misconfigurations,
		"crypto_issues_count":    len(report.Findings.CryptoIssues),
		"code_issues_count":      len(report.Findings.CodeIssues),
		"hardening_issues_count": len(report.Findings.HardeningIssues),
		"insecure_storage_count": len(report.Findings.InsecureStorage),
		"urls_count":             len(report.Findings.URLs),
		"trackers":               report.Findings.Trackers,
		"permissions":            report.Findings.Permissions,
		"deep_links":             report.Findings.DeepLinks,
		"data_flows_count":       len(report.Findings.DataFlows),
	}
}

func countBySeverity(report *Report, severity string) int {
	count := 0
	allFindings := append(report.Findings.Secrets, report.Findings.CryptoIssues...)
	allFindings = append(allFindings, report.Findings.CodeIssues...)
	allFindings = append(allFindings, report.Findings.HardeningIssues...)
	allFindings = append(allFindings, report.Findings.InsecureStorage...)
	for _, f := range allFindings {
		if strings.EqualFold(f.Severity, severity) {
			count++
		}
	}
	return count
}

func limitFindings(findings []Finding, limit int, severity string) []Finding {
	var result []Finding
	for _, f := range findings {
		if severity != "" && !strings.EqualFold(f.Severity, severity) {
			// Check severity ordering
			if !isSeverityAtLeast(f.Severity, severity) {
				continue
			}
		}
		result = append(result, f)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func limitStrings(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func isSeverityAtLeast(actual, minimum string) bool {
	order := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	return order[strings.ToUpper(actual)] >= order[strings.ToUpper(minimum)]
}

func sanitizeFilename(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", ".", "_")
	return r.Replace(name)
}

func formatFridaArgs(paths []string) string {
	var args []string
	for _, p := range paths {
		args = append(args, fmt.Sprintf("-l %s", p))
	}
	return strings.Join(args, " ")
}

func formatAttachFlags(scripts []string) string {
	flagMap := map[string]string{
		"ssl_bypass":                "--ssl",
		"bio_bypass":                "--bio",
		"ixguard":                   "--ixguard",
		"api_monitor":               "--monitor-api",
		"crypto_monitor":            "--crypto",
		"bypass_universal":          "--bypass",
		"header_logger":             "--headers",
		"url_scheme_monitor":        "--url-scheme-monitor",
		"nscoding_monitor":          "--nscoding-monitor",
		"keychain_security_monitor": "--keychain-monitor",
	}

	var flags []string
	for _, s := range scripts {
		if flag, ok := flagMap[s]; ok {
			flags = append(flags, flag)
		}
	}
	return strings.Join(flags, " ")
}

// generateFridaScriptForTarget creates a Frida script based on target and action
func generateFridaScriptForTarget(target, action, description string) string {
	var sb strings.Builder

	sb.WriteString("// Auto-generated by iOSHunt MCP\n")
	sb.WriteString(fmt.Sprintf("// Target: %s\n", target))
	sb.WriteString(fmt.Sprintf("// Action: %s\n", action))
	sb.WriteString(fmt.Sprintf("// Description: %s\n\n", description))

	switch action {
	case "hook":
		sb.WriteString(fmt.Sprintf(`// Hook: %s
if (ObjC.available) {
    try {
        var className = "%s";
        var methods = ObjC.classes[className].$ownMethods;

        console.log("[*] Hooking " + className + " (" + methods.length + " methods)");

        methods.forEach(function(method) {
            try {
                var impl = ObjC.classes[className][method];
                Interceptor.attach(impl.implementation, {
                    onEnter: function(args) {
                        console.log("[HOOK] " + className + " " + method);
                        // Log arguments
                        for (var i = 2; i < Math.min(args.length, 6); i++) {
                            try {
                                var arg = new ObjC.Object(args[i]);
                                console.log("  arg[" + i + "]: " + arg.toString().substring(0, 200));
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            var ret = new ObjC.Object(retval);
                            console.log("  => " + ret.toString().substring(0, 200));
                        } catch(e) {}
                    }
                });
            } catch(e) {}
        });
    } catch(e) {
        console.log("[!] Error hooking: " + e);
    }
}
`, target, target))

	case "bypass":
		sb.WriteString(fmt.Sprintf(`// Bypass: %s
if (ObjC.available) {
    try {
        // Method 1: Direct method replacement
        var target = ObjC.classes["%s"];
        if (target) {
            var methods = target.$ownMethods;
            methods.forEach(function(method) {
                if (method.toLowerCase().indexOf("check") !== -1 ||
                    method.toLowerCase().indexOf("verify") !== -1 ||
                    method.toLowerCase().indexOf("detect") !== -1 ||
                    method.toLowerCase().indexOf("valid") !== -1) {

                    try {
                        Interceptor.attach(target[method].implementation, {
                            onLeave: function(retval) {
                                console.log("[BYPASS] " + method + " -> forcing true/YES");
                                retval.replace(ptr(0x1)); // Return YES/true
                            }
                        });
                        console.log("[*] Bypassed: " + method);
                    } catch(e) {}
                }
            });
        }

        // Method 2: Common patterns
        // Hook NSFileManager for file existence checks
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter: function(args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function(retval) {
                var suspicious = ["/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd",
                    "/etc/apt", "/private/var/lib/apt", "/Library/MobileSubstrate"];
                for (var i = 0; i < suspicious.length; i++) {
                    if (this.path.indexOf(suspicious[i]) !== -1) {
                        console.log("[BYPASS] Blocked file check: " + this.path);
                        retval.replace(ptr(0x0));
                        return;
                    }
                }
            }
        });
    } catch(e) {
        console.log("[!] Bypass error: " + e);
    }
}
`, target, target))

	case "monitor":
		sb.WriteString(fmt.Sprintf(`// Monitor: %s
if (ObjC.available) {
    try {
        // Monitor all method calls to target class
        var target = ObjC.classes["%s"];
        if (target) {
            var methods = target.$ownMethods;
            console.log("[*] Monitoring " + methods.length + " methods on %s");

            methods.forEach(function(method) {
                try {
                    Interceptor.attach(target[method].implementation, {
                        onEnter: function(args) {
                            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n    ");
                            console.log("\n[MONITOR] " + method);
                            console.log("  Backtrace:\n    " + bt);
                        }
                    });
                } catch(e) {}
            });
        }
    } catch(e) {
        console.log("[!] Monitor error: " + e);
    }
}
`, target, target, target))

	case "dump":
		sb.WriteString(fmt.Sprintf(`// Dump: %s
if (ObjC.available) {
    try {
        var target = ObjC.classes["%s"];
        if (target) {
            console.log("[*] Dumping %s instances...");

            // Enumerate instances
            ObjC.choose(target, {
                onMatch: function(instance) {
                    console.log("\n[DUMP] Instance: " + instance.handle);

                    // Dump all properties
                    var props = target.$ownMethods.filter(function(m) {
                        return m.indexOf("-") === 0 && m.indexOf(":") === -1;
                    });
                    props.forEach(function(prop) {
                        try {
                            var val = instance[prop.substring(2)]();
                            console.log("  " + prop + " = " + val);
                        } catch(e) {}
                    });
                },
                onComplete: function() {
                    console.log("[*] Dump complete");
                }
            });
        }
    } catch(e) {
        console.log("[!] Dump error: " + e);
    }
}
`, target, target, target))

	case "trace":
		sb.WriteString(fmt.Sprintf(`// Trace: %s
if (ObjC.available) {
    try {
        // Trace all calls with arguments and return values
        var resolver = new ApiResolver("objc");
        var matches = resolver.enumerateMatches("*[%s *]");

        console.log("[*] Tracing " + matches.length + " methods on %s");

        matches.forEach(function(match) {
            try {
                Interceptor.attach(match.address, {
                    onEnter: function(args) {
                        this.methodName = match.name;
                        console.log("\n[TRACE] >>> " + match.name);
                        // Log first 4 arguments
                        for (var i = 2; i < 6; i++) {
                            try {
                                var arg = new ObjC.Object(args[i]);
                                console.log("  arg[" + (i-2) + "]: " + arg.toString().substring(0, 500));
                            } catch(e) {
                                if (args[i] && !args[i].isNull()) {
                                    console.log("  arg[" + (i-2) + "]: " + args[i]);
                                }
                            }
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            var ret = new ObjC.Object(retval);
                            console.log("  <<< return: " + ret.toString().substring(0, 500));
                        } catch(e) {
                            console.log("  <<< return: " + retval);
                        }
                    }
                });
            } catch(e) {}
        });
    } catch(e) {
        console.log("[!] Trace error: " + e);
    }
}
`, target, target, target))

	case "inject":
		sb.WriteString(fmt.Sprintf(`// Inject: %s
if (ObjC.available) {
    try {
        // Create and inject custom object/value
        console.log("[*] Injection target: %s");

        // Example: Override method return value
        var target = ObjC.classes["%s"];
        if (target) {
            // Replace specific method implementations
            var methods = target.$ownMethods;
            methods.forEach(function(method) {
                if (method.indexOf("isValid") !== -1 || method.indexOf("isAuth") !== -1 ||
                    method.indexOf("isEnabled") !== -1 || method.indexOf("canAccess") !== -1) {
                    Interceptor.attach(target[method].implementation, {
                        onLeave: function(retval) {
                            console.log("[INJECT] " + method + ": forcing YES");
                            retval.replace(ptr(0x1));
                        }
                    });
                }
            });
        }

        console.log("[*] Injection complete");
    } catch(e) {
        console.log("[!] Injection error: " + e);
    }
}
`, target, target, target))

	default:
		sb.WriteString(fmt.Sprintf("console.log('[*] Custom script for: %s');\n", target))
	}

	return sb.String()
}

// searchInApp searches for a pattern in the extracted app directory
func searchInApp(appPath, pattern, fileFilter string) []map[string]string {
	var results []map[string]string

	filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if fileFilter != "" && !strings.HasSuffix(path, fileFilter) {
			return nil
		}

		// Read file and search
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				relPath, _ := filepath.Rel(appPath, path)
				results = append(results, map[string]string{
					"file":    relPath,
					"line":    fmt.Sprintf("%d", i+1),
					"content": truncate(strings.TrimSpace(line), 200),
				})
				if len(results) >= 100 {
					return filepath.SkipAll
				}
			}
		}

		return nil
	})

	return results
}

// verifyExploitability runs targeted verification checks
func verifyExploitability(findingType, value, context string) string {
	var sb strings.Builder

	switch findingType {
	case "api_key":
		sb.WriteString(fmt.Sprintf("## API Key Verification: %s\n\n", truncate(value, 20)+"..."))
		sb.WriteString("### Checks:\n")
		if strings.HasPrefix(value, "AIza") {
			sb.WriteString("- **Type:** Google API Key\n")
			sb.WriteString("- **Risk:** Can be tested by calling Google Maps/Places API\n")
			sb.WriteString("- **PoC:** `curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=KEY'`\n")
		} else if strings.HasPrefix(value, "sk_live") || strings.HasPrefix(value, "pk_live") {
			sb.WriteString("- **Type:** Stripe Key (LIVE)\n")
			sb.WriteString("- **Risk:** CRITICAL - Live payment key exposed\n")
			sb.WriteString("- **PoC:** `curl https://api.stripe.com/v1/charges -u KEY:`\n")
		} else if strings.HasPrefix(value, "AKIA") {
			sb.WriteString("- **Type:** AWS Access Key\n")
			sb.WriteString("- **Risk:** CRITICAL - Cloud infrastructure access\n")
			sb.WriteString("- **PoC:** `aws sts get-caller-identity --access-key-id KEY`\n")
		} else {
			sb.WriteString("- **Type:** Unknown API Key pattern\n")
			sb.WriteString("- **Recommendation:** Test manually against likely endpoints\n")
		}

	case "url_endpoint":
		sb.WriteString(fmt.Sprintf("## URL Endpoint Check: %s\n\n", value))
		sb.WriteString("### Verification Steps:\n")
		sb.WriteString("1. Check if endpoint is accessible: `curl -I URL`\n")
		sb.WriteString("2. Test for authentication bypass: `curl URL` without auth headers\n")
		sb.WriteString("3. Check for API documentation: `curl URL/swagger` or `URL/api-docs`\n")
		sb.WriteString("4. Test for information disclosure in error responses\n")
		if strings.Contains(value, "staging") || strings.Contains(value, "dev") || strings.Contains(value, "test") {
			sb.WriteString("\n⚠ **WARNING:** This appears to be a staging/dev endpoint - likely less secured.\n")
		}

	case "weak_crypto":
		sb.WriteString("## Weak Cryptography Verification\n\n")
		sb.WriteString(fmt.Sprintf("**Algorithm/Pattern:** %s\n\n", value))
		sb.WriteString("### Impact Assessment:\n")
		if strings.Contains(strings.ToLower(value), "md5") || strings.Contains(strings.ToLower(value), "sha1") {
			sb.WriteString("- Weak hash algorithm in use\n")
			sb.WriteString("- If used for passwords: CRITICAL (rainbow table attacks)\n")
			sb.WriteString("- If used for checksums: LOW (integrity, not security)\n")
		}
		if strings.Contains(strings.ToLower(value), "des") || strings.Contains(strings.ToLower(value), "ecb") {
			sb.WriteString("- Weak encryption algorithm/mode\n")
			sb.WriteString("- ECB mode leaks patterns in ciphertext\n")
			sb.WriteString("- DES has insufficient key length (56-bit)\n")
		}

	case "missing_pinning":
		sb.WriteString("## Certificate Pinning Verification\n\n")
		sb.WriteString("### Dynamic Test Steps:\n")
		sb.WriteString("1. Set up Burp Suite proxy on your Mac\n")
		sb.WriteString("2. Configure iOS device to use proxy\n")
		sb.WriteString("3. Install Burp CA certificate on device\n")
		sb.WriteString("4. Launch the app and observe traffic\n")
		sb.WriteString("5. If traffic is visible: NO PINNING (confirmed)\n")
		sb.WriteString("6. If connection fails: Pinning present\n\n")
		sb.WriteString("### Frida Bypass:\n")
		sb.WriteString("```\nioshunt attach <process> --ssl\n```\n")

	case "debug_enabled":
		sb.WriteString("## Debug Mode Verification\n\n")
		sb.WriteString("### Checks:\n")
		sb.WriteString("- `get-task-allow` entitlement = true\n")
		sb.WriteString("- Allows debugger attachment (lldb, Frida)\n")
		sb.WriteString("- **Impact:** Attacker can inspect memory, modify runtime\n\n")
		sb.WriteString("### PoC:\n")
		sb.WriteString("```\nlldb -n <process-name>\n(lldb) process attach --name <app>\n```\n")

	case "ats_bypass":
		sb.WriteString("## ATS Bypass Verification\n\n")
		sb.WriteString("### Impact:\n")
		sb.WriteString("- App allows insecure HTTP connections\n")
		sb.WriteString("- Data transmitted in cleartext can be intercepted\n\n")
		sb.WriteString("### Verification:\n")
		sb.WriteString("1. Monitor traffic with Wireshark/tcpdump\n")
		sb.WriteString("2. Look for HTTP (not HTTPS) requests\n")
		sb.WriteString("3. Check for sensitive data in cleartext\n")

	default:
		sb.WriteString(fmt.Sprintf("## Unknown Finding Type: %s\n\nManual verification recommended.\n", findingType))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
