package core

// MCP tool implementations for runtime verification, reproduction,
// evidence capture, sideloading, and the autonomous hunt pipeline.
//
// Implementations live here (separate from mcp.go) to keep concerns split.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// netCaptureRegistry holds active rvictl pcap sessions across MCP calls
var (
	netCaptureMu sync.Mutex
	netCaptures  = map[string]*NetCaptureHandle{} // key = device_udid
)

// ---------------------------------------------------------------------------
// ios_live_verify
// ---------------------------------------------------------------------------

func (s *MCPServer) toolLiveVerify(args json.RawMessage) mcpToolResult {
	var p struct {
		BundleID     string `json:"bundle_id"`
		OnlySeverity string `json:"only_severity"`
		MaxFindings  int    `json:"max_findings"`
		OutputDir    string `json:"output_dir"`
	}
	json.Unmarshal(args, &p)
	if p.BundleID == "" {
		return mcpError("bundle_id is required")
	}
	if p.OnlySeverity == "" {
		p.OnlySeverity = "HIGH"
	}
	if p.MaxFindings == 0 {
		p.MaxFindings = 30
	}

	report, err := s.loadReport(p.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}

	candidates := collectVerifiable(report, p.OnlySeverity, p.MaxFindings)
	if len(candidates) == 0 {
		return mcpSuccess(fmt.Sprintf("No findings >= %s eligible for live verification.", p.OnlySeverity))
	}

	tester := NewLiveTester(p.OutputDir)
	results := tester.VerifyAll(candidates)

	// Persist updated report (with LiveStatus / Evidence)
	if s.session.ReportPath != "" {
		_ = report.SaveJSON(s.session.ReportPath)
	}

	saved, _ := tester.SaveResults(results)
	confirmed := 0
	for _, r := range results {
		if r.Status == "CONFIRMED" {
			confirmed++
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Live Verification Complete\n\n")
	fmt.Fprintf(&sb, "- Probed: %d findings (severity >= %s)\n", len(results), p.OnlySeverity)
	fmt.Fprintf(&sb, "- **CONFIRMED EXPLOITABLE: %d**\n", confirmed)
	fmt.Fprintf(&sb, "- Evidence dir: %s\n", tester.OutputDir)
	if saved != "" {
		fmt.Fprintf(&sb, "- Results JSON: %s\n\n", saved)
	}
	fmt.Fprintf(&sb, "### Findings:\n")
	for _, r := range results {
		mark := "·"
		if r.Status == "CONFIRMED" {
			mark = "[!]"
		}
		fmt.Fprintf(&sb, "- %s [%s] %s — %s\n", mark, r.Status, r.Provider, snippet(r.Detail, 200))
	}
	return mcpSuccess(sb.String())
}

// ---------------------------------------------------------------------------
// ios_reproduce_finding
// ---------------------------------------------------------------------------

func (s *MCPServer) toolReproduceFinding(args json.RawMessage) mcpToolResult {
	var p struct {
		BundleID     string  `json:"bundle_id"`
		FindingID    string  `json:"finding_id"`
		Category     string  `json:"category"`
		DurationSec  float64 `json:"duration_sec"`
		Spawn        bool    `json:"spawn"`
		OnlySeverity string  `json:"only_severity"`
	}
	json.Unmarshal(args, &p)
	if p.BundleID == "" {
		return mcpError("bundle_id is required")
	}

	report, err := s.loadReport(p.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}

	all := flattenFindings(report)
	for _, f := range all {
		if f.ID == "" {
			f.ID = ComputeFindingID(f)
		}
	}

	// Filter
	var targets []*Finding
	switch {
	case p.FindingID != "":
		for _, f := range all {
			if f.ID == p.FindingID {
				targets = append(targets, f)
				break
			}
		}
		if len(targets) == 0 {
			return mcpError("finding_id %s not found", p.FindingID)
		}
	case p.Category != "":
		for _, f := range all {
			if strings.EqualFold(f.Category, p.Category) {
				targets = append(targets, f)
			}
		}
	default:
		targets = all
	}
	if p.OnlySeverity != "" {
		filtered := targets[:0]
		for _, f := range targets {
			if isSeverityAtLeast(f.Severity, p.OnlySeverity) {
				filtered = append(filtered, f)
			}
		}
		targets = filtered
	}
	if len(targets) == 0 {
		return mcpSuccess("No findings matched the filter for reproduction.")
	}

	collector := NewEvidenceCollector("")
	engine := NewReproEngine(p.BundleID, collector)
	engine.Spawn = p.Spawn
	if p.DurationSec > 0 {
		engine.Duration = time.Duration(p.DurationSec) * time.Second
	}

	results := engine.ReproduceAll(targets)

	if s.session.ReportPath != "" {
		_ = report.SaveJSON(s.session.ReportPath)
	}

	confirmed := 0
	for _, r := range results {
		if r.Reproduced {
			confirmed++
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Dynamic Reproduction Complete\n\n")
	fmt.Fprintf(&sb, "- Targets: %d findings\n", len(results))
	fmt.Fprintf(&sb, "- **REPRODUCED ON DEVICE: %d**\n", confirmed)
	fmt.Fprintf(&sb, "- Evidence session: %s\n\n", collector.OutputDir)
	for _, r := range results {
		mark := "·"
		if r.Reproduced {
			mark = "[!]"
		}
		fmt.Fprintf(&sb, "- %s [%s] %s (script=%s, hits=%d)\n", mark, r.Status, r.Title, r.Script, r.Hits)
		if r.Error != "" {
			fmt.Fprintf(&sb, "    err: %s\n", r.Error)
		}
		if r.OutputPath != "" {
			fmt.Fprintf(&sb, "    log: %s\n", r.OutputPath)
		}
	}
	return mcpSuccess(sb.String())
}

// ---------------------------------------------------------------------------
// ios_capture_evidence
// ---------------------------------------------------------------------------

func (s *MCPServer) toolCaptureEvidence(args json.RawMessage) mcpToolResult {
	var p struct {
		Action     string `json:"action"`
		FindingID  string `json:"finding_id"`
		DeviceUDID string `json:"device_udid"`
	}
	json.Unmarshal(args, &p)
	if p.Action == "" {
		return mcpError("action is required (screenshot|netcap_start|netcap_stop|bundle)")
	}

	collector := NewEvidenceCollector("")

	switch p.Action {
	case "screenshot":
		path, err := collector.CaptureScreenshot(p.FindingID, p.DeviceUDID)
		if err != nil {
			return mcpError("screenshot failed: %v", err)
		}
		s.attachEvidenceToFinding(p.FindingID, "screenshot", path, "Device screenshot")
		return mcpSuccess(fmt.Sprintf("Screenshot saved: %s", path))

	case "netcap_start":
		if p.DeviceUDID == "" {
			return mcpError("device_udid required for netcap_start")
		}
		netCaptureMu.Lock()
		defer netCaptureMu.Unlock()
		if _, ok := netCaptures[p.DeviceUDID]; ok {
			return mcpError("netcap already running for %s; call netcap_stop first", p.DeviceUDID)
		}
		h, err := collector.StartNetworkCapture(p.FindingID, p.DeviceUDID)
		if err != nil {
			return mcpError("netcap_start failed: %v", err)
		}
		netCaptures[p.DeviceUDID] = h
		return mcpSuccess(fmt.Sprintf("Network capture started → %s\n(stop via netcap_stop)", h.PcapPath))

	case "netcap_stop":
		if p.DeviceUDID == "" {
			return mcpError("device_udid required for netcap_stop")
		}
		netCaptureMu.Lock()
		h, ok := netCaptures[p.DeviceUDID]
		if !ok {
			netCaptureMu.Unlock()
			return mcpError("no active netcap for %s", p.DeviceUDID)
		}
		delete(netCaptures, p.DeviceUDID)
		netCaptureMu.Unlock()
		_ = h.Stop()
		s.attachEvidenceToFinding(p.FindingID, "network", h.PcapPath, "rvictl pcap")
		return mcpSuccess(fmt.Sprintf("Network capture stopped: %s", h.PcapPath))

	case "bundle":
		path, err := collector.BundleSession()
		if err != nil {
			return mcpError("bundle failed: %v", err)
		}
		return mcpSuccess(fmt.Sprintf("Evidence bundle: %s", path))
	}
	return mcpError("unknown action: %s", p.Action)
}

// ---------------------------------------------------------------------------
// ios_sideload
// ---------------------------------------------------------------------------

func (s *MCPServer) toolSideload(args json.RawMessage) mcpToolResult {
	var p struct {
		Action     string `json:"action"`
		IPAPath    string `json:"ipa_path"`
		BundleID   string `json:"bundle_id"`
		DeviceUDID string `json:"device_udid"`
		Method     string `json:"method"`
		Launch     bool   `json:"launch"`
	}
	json.Unmarshal(args, &p)

	switch p.Action {
	case "list_devices":
		devs, err := ListSideloadDevices()
		if err != nil {
			return mcpError("%v", err)
		}
		js, _ := json.MarshalIndent(devs, "", "  ")
		return mcpSuccess(fmt.Sprintf("Found %d device(s):\n%s", len(devs), string(js)))

	case "pair":
		if err := PairDevice(p.DeviceUDID); err != nil {
			return mcpError("%v", err)
		}
		return mcpSuccess("Pairing succeeded.")

	case "install":
		if p.IPAPath == "" {
			// auto-find latest re-signed IPA
			matches, _ := filepath.Glob("*.ipa")
			for _, m := range matches {
				if strings.Contains(strings.ToLower(m), "resigned") || strings.Contains(strings.ToLower(m), "patched") {
					p.IPAPath = m
					break
				}
			}
			if p.IPAPath == "" && len(matches) > 0 {
				p.IPAPath = matches[len(matches)-1]
			}
		}
		if p.IPAPath == "" {
			return mcpError("ipa_path is required")
		}
		res := Sideload(SideloadOptions{
			IPAPath:    p.IPAPath,
			BundleID:   p.BundleID,
			DeviceUDID: p.DeviceUDID,
			Method:     p.Method,
			Launch:     p.Launch,
		})
		out, _ := json.MarshalIndent(res, "", "  ")
		if !res.Success {
			return mcpToolResult{Content: []mcpContent{{Type: "text", Text: string(out)}}, IsError: true}
		}
		return mcpSuccess(string(out))

	case "uninstall":
		if p.BundleID == "" {
			return mcpError("bundle_id required")
		}
		if err := UninstallApp(p.DeviceUDID, p.BundleID); err != nil {
			return mcpError("%v", err)
		}
		return mcpSuccess("Uninstalled " + p.BundleID)

	case "list_apps":
		bundles, err := ListInstalledApps(p.DeviceUDID)
		if err != nil {
			return mcpError("%v", err)
		}
		return mcpSuccess(fmt.Sprintf("%d apps installed:\n%s", len(bundles), strings.Join(bundles, "\n")))
	}
	return mcpError("unknown action: %s", p.Action)
}

// ---------------------------------------------------------------------------
// ios_auto_hunt — full pipeline
// ---------------------------------------------------------------------------

func (s *MCPServer) toolAutoHunt(args json.RawMessage) mcpToolResult {
	var p struct {
		BundleID     string  `json:"bundle_id"`
		IPAPath      string  `json:"ipa_path"`
		SkipRecon    bool    `json:"skip_recon"`
		SkipLive     bool    `json:"skip_live"`
		SkipRepro    bool    `json:"skip_repro"`
		OnlySeverity string  `json:"only_severity"`
		DeviceUDID   string  `json:"device_udid"`
		DurationSec  float64 `json:"duration_sec"`
	}
	json.Unmarshal(args, &p)
	if p.BundleID == "" {
		return mcpError("bundle_id is required")
	}
	if p.OnlySeverity == "" {
		p.OnlySeverity = "HIGH"
	}

	var report *Report
	var sb strings.Builder
	fmt.Fprintf(&sb, "# AutoHunt Pipeline — %s\n\n", p.BundleID)

	// Phase 1 — Recon
	if !p.SkipRecon {
		recargs, _ := json.Marshal(map[string]interface{}{
			"bundle_id": p.BundleID,
			"ipa_path":  p.IPAPath,
		})
		res := s.toolRecon(recargs)
		if res.IsError {
			return res
		}
		fmt.Fprintf(&sb, "## Phase 1 — Static Recon\n%s\n\n", contentText(res))
	} else {
		fmt.Fprintf(&sb, "## Phase 1 — Static Recon  [SKIPPED]\n\n")
	}

	r, err := s.loadReport(p.BundleID)
	if err != nil {
		return mcpError("%v", err)
	}
	report = r

	collector := NewEvidenceCollector("")

	// Phase 2 — Live verify
	if !p.SkipLive {
		candidates := collectVerifiable(report, p.OnlySeverity, 50)
		tester := NewLiveTester(filepath.Join(collector.OutputDir, "livetest"))
		results := tester.VerifyAll(candidates)
		conf := 0
		for _, r := range results {
			if r.Status == "CONFIRMED" {
				conf++
			}
		}
		fmt.Fprintf(&sb, "## Phase 2 — Live Verification\n- probed: %d, **confirmed: %d**\n\n", len(results), conf)
	} else {
		fmt.Fprintf(&sb, "## Phase 2 — Live Verification  [SKIPPED]\n\n")
	}

	// Phase 3 — On-device reproduction
	if !p.SkipRepro {
		all := flattenFindings(report)
		var targets []*Finding
		for _, f := range all {
			if f.ID == "" {
				f.ID = ComputeFindingID(f)
			}
			if isSeverityAtLeast(f.Severity, p.OnlySeverity) {
				targets = append(targets, f)
			}
		}
		engine := NewReproEngine(p.BundleID, collector)
		if p.DurationSec > 0 {
			engine.Duration = time.Duration(p.DurationSec) * time.Second
		}
		rs := engine.ReproduceAll(targets)
		repCount := 0
		for _, r := range rs {
			if r.Reproduced {
				repCount++
			}
		}
		fmt.Fprintf(&sb, "## Phase 3 — Dynamic Reproduction\n- targets: %d, **reproduced: %d**\n\n", len(rs), repCount)
	} else {
		fmt.Fprintf(&sb, "## Phase 3 — Dynamic Reproduction  [SKIPPED]\n\n")
	}

	// Phase 4 — Persist updated report + bundle evidence
	if s.session.ReportPath != "" {
		_ = report.SaveJSON(s.session.ReportPath)
	}
	bundle, err := collector.BundleSession()
	if err == nil {
		fmt.Fprintf(&sb, "## Phase 4 — Evidence Bundle\n- %s\n\n", bundle)
	}

	// Phase 5 — Final summary
	verified := 0
	reproduced := 0
	for _, f := range flattenFindings(report) {
		if f.LiveVerified {
			verified++
		}
		if f.Reproduced {
			reproduced++
		}
	}
	fmt.Fprintf(&sb, "## Summary\n- live-verified: **%d**\n- reproduced-on-device: **%d**\n", verified, reproduced)
	fmt.Fprintf(&sb, "- report: %s\n", s.session.ReportPath)

	return mcpSuccess(sb.String())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// flattenFindings returns pointers to all Finding objects across categories.
// Mutating the returned pointers updates the underlying slices.
func flattenFindings(r *Report) []*Finding {
	var out []*Finding
	add := func(slice []Finding, cat string) []Finding {
		for i := range slice {
			if slice[i].Category == "" {
				slice[i].Category = cat
			}
			if slice[i].ID == "" {
				slice[i].ID = ComputeFindingID(&slice[i])
			}
			out = append(out, &slice[i])
		}
		return slice
	}
	r.Findings.Secrets = add(r.Findings.Secrets, "secret")
	r.Findings.HardeningIssues = add(r.Findings.HardeningIssues, "hardening")
	r.Findings.InsecureStorage = add(r.Findings.InsecureStorage, "storage")
	r.Findings.CryptoIssues = add(r.Findings.CryptoIssues, "crypto")
	r.Findings.CodeIssues = add(r.Findings.CodeIssues, "code")
	return out
}

// collectVerifiable picks findings eligible for live HTTP probing
func collectVerifiable(r *Report, minSev string, max int) []*Finding {
	var out []*Finding
	for _, f := range flattenFindings(r) {
		if !isSeverityAtLeast(f.Severity, minSev) {
			continue
		}
		// Has a probe-able value (URL, API key, etc.)
		if f.Value != "" || strings.Contains(strings.ToLower(f.Title), "url") || strings.Contains(strings.ToLower(f.Title), "ats") {
			out = append(out, f)
		}
		if len(out) >= max {
			break
		}
	}
	// Also add URLs from r.Findings.URLs as synthetic findings
	for _, u := range r.Findings.URLs {
		if !strings.HasPrefix(u, "http") {
			continue
		}
		f := &Finding{
			Title:    "Extracted URL",
			Value:    u,
			FilePath: "binary",
			Severity: "MEDIUM",
			Category: "url",
		}
		f.ID = ComputeFindingID(f)
		out = append(out, f)
		if len(out) >= max {
			break
		}
	}
	return out
}

func (s *MCPServer) attachEvidenceToFinding(findingID, evType, path, desc string) {
	if findingID == "" || s.session.Report == nil {
		return
	}
	for _, f := range flattenFindings(s.session.Report) {
		if f.ID == findingID {
			f.Evidence = append(f.Evidence, Evidence{
				Type: evType, Path: path, Description: desc,
				CapturedAt: time.Now().UTC().Format(time.RFC3339),
			})
			st, _ := os.Stat(path)
			if st != nil {
				f.Evidence[len(f.Evidence)-1].Size = st.Size()
			}
			break
		}
	}
	if s.session.ReportPath != "" {
		_ = s.session.Report.SaveJSON(s.session.ReportPath)
	}
}

func contentText(r mcpToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}
