package core

// Auto-reproduction engine: maps each static finding to a Frida hook
// that confirms the issue at runtime on a real device.
//
// Workflow per finding:
//   1. Pick a category-specific Frida script (auto_repro_*.js)
//   2. Spawn frida -U -n <bundle> -l <script> with timeout
//   3. Capture stdout, scan for "[REPRO_HIT]" markers
//   4. Save log as evidence, mark Finding.Reproduced = true|false
//
// Works with non-JB devices when FridaGadget has been injected and the
// re-signed app is running. Falls back gracefully if frida is unavailable.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ReproEngine drives dynamic finding verification on a connected device
type ReproEngine struct {
	BundleID  string
	DeviceID  string         // empty = first USB device
	Duration  time.Duration  // hook attach window
	Collector *EvidenceCollector
	Spawn     bool          // true: -f spawn, false: -n attach to running
	Verbose   bool
}

// NewReproEngine returns a sane default
func NewReproEngine(bundleID string, collector *EvidenceCollector) *ReproEngine {
	if collector == nil {
		collector = NewEvidenceCollector("")
	}
	return &ReproEngine{
		BundleID:  bundleID,
		Duration:  20 * time.Second,
		Collector: collector,
	}
}

// ReproResult is the outcome of a single dynamic reproduction
type ReproResult struct {
	FindingID    string `json:"finding_id"`
	Title        string `json:"title"`
	Script       string `json:"script"`
	Status       string `json:"status"` // REPRODUCED / NOT_TRIGGERED / FAILED / SKIPPED
	Hits         int    `json:"hits"`
	OutputPath   string `json:"output_path,omitempty"`
	Error        string `json:"error,omitempty"`
	DurationSec  int    `json:"duration_sec"`
	Reproduced   bool   `json:"reproduced"`
}

// ReproduceAll runs hooks for each finding sequentially.
// To avoid attaching the same script repeatedly, identical scripts are batched.
func (r *ReproEngine) ReproduceAll(findings []*Finding) []ReproResult {
	results := make([]ReproResult, 0, len(findings))
	// group findings by chosen script
	byScript := make(map[string][]*Finding)
	for _, f := range findings {
		if f.ID == "" {
			f.ID = ComputeFindingID(f)
		}
		script := selectScriptFor(f)
		if script == "" {
			results = append(results, ReproResult{
				FindingID: f.ID, Title: f.Title, Status: "SKIPPED",
				Error: "no auto-repro script for category: " + f.Category,
			})
			continue
		}
		byScript[script] = append(byScript[script], f)
	}

	for script, group := range byScript {
		out, err := r.runFridaHook(script)
		hits := countReproHits(out)
		status := "NOT_TRIGGERED"
		reproduced := false
		if err != nil {
			status = "FAILED"
		} else if hits > 0 {
			status = "REPRODUCED"
			reproduced = true
		}

		// Per-finding result (all in this group share the script outcome
		// but each correlates if its Value/Snippet appears in output)
		for _, f := range group {
			individualHits := countMatches(out, f)
			indReproduced := reproduced && (individualHits > 0 || hits > 0 && f.Value == "")
			indStatus := status
			if status == "REPRODUCED" && individualHits == 0 && f.Value != "" {
				indStatus = "NOT_TRIGGERED"
				indReproduced = false
			}

			path, _ := r.Collector.SaveFridaOutput(f.ID, script, out)

			res := ReproResult{
				FindingID:   f.ID,
				Title:       f.Title,
				Script:      script,
				Status:      indStatus,
				Hits:        individualHits,
				OutputPath:  path,
				DurationSec: int(r.Duration.Seconds()),
				Reproduced:  indReproduced,
			}
			if err != nil {
				res.Error = err.Error()
			}
			results = append(results, res)

			// Mutate finding
			f.Reproduced = indReproduced
			f.ReproStatus = indStatus
			f.ReproScript = script
			f.ReproDuration = res.DurationSec
			if path != "" {
				f.ReproOutput = path
				r.Collector.AttachToFinding(f, "hook_log", path,
					fmt.Sprintf("Auto-repro %s — %d hits", script, individualHits))
			}
		}
	}

	return results
}

// runFridaHook executes one Frida script for r.Duration and returns combined output
func (r *ReproEngine) runFridaHook(scriptAsset string) (string, error) {
	scriptPath, err := GetAssetScript(scriptAsset)
	if err != nil {
		return "", fmt.Errorf("script not found: %s", scriptAsset)
	}
	if _, err := exec.LookPath("frida"); err != nil {
		return "", fmt.Errorf("frida CLI not installed")
	}

	args := []string{"-U", "--no-pause", "-l", scriptPath}
	if r.Spawn {
		args = append(args, "-f", r.BundleID)
	} else {
		args = append(args, "-n", r.BundleID)
	}
	if r.DeviceID != "" {
		// frida uses --device <id>
		args = append([]string{"--device", r.DeviceID}, args[1:]...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.Duration)
	defer cancel()

	cmd := exec.CommandContext(ctx, "frida", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Stdin = strings.NewReader("\nq\n") // quit cleanly when context expires

	if r.Verbose {
		fmt.Printf("[repro] frida %s\n", strings.Join(args, " "))
	}
	_ = cmd.Run() // timeout will kill it; we still want the buffer

	out := buf.String()
	if out == "" {
		return "", fmt.Errorf("frida produced no output (process not attached?)")
	}
	return out, nil
}

// selectScriptFor maps a finding's category/title to a Frida asset script
func selectScriptFor(f *Finding) string {
	cat := strings.ToLower(f.Category)
	title := strings.ToLower(f.Title)
	snip := strings.ToLower(f.Snippet)

	// API keys / secrets — we want to see them transmitted
	if cat == "secret" || strings.Contains(title, "api key") || strings.Contains(title, "secret") || strings.Contains(title, "token") {
		return "auto_repro_network.js"
	}
	// URL endpoints — same network monitor
	if cat == "url" || strings.Contains(title, "url") || strings.Contains(title, "endpoint") {
		return "auto_repro_network.js"
	}
	// Insecure storage — file I/O monitor
	if cat == "storage" || strings.Contains(title, "storage") || strings.Contains(title, "nsuserdefaults") || strings.Contains(title, "plist") {
		return "auto_repro_storage.js"
	}
	// Keychain
	if strings.Contains(title, "keychain") {
		return "auto_repro_keychain.js"
	}
	// Crypto issues
	if cat == "crypto" || strings.Contains(title, "md5") || strings.Contains(title, "sha1") || strings.Contains(title, "des") || strings.Contains(title, "ecb") || strings.Contains(title, "weak") {
		return "auto_repro_crypto.js"
	}
	// URL schemes / deep links
	if strings.Contains(title, "url scheme") || strings.Contains(title, "deep link") || strings.Contains(snip, "openurl") {
		return "auto_repro_url_scheme.js"
	}
	// Cert pinning
	if strings.Contains(title, "pinning") || strings.Contains(title, "ssl") {
		return "ssl_bypass.js"
	}
	// Jailbreak detection
	if strings.Contains(title, "jailbreak") {
		return "bypass_universal.js"
	}
	return ""
}

// countReproHits counts our standardized markers in Frida output
func countReproHits(out string) int {
	return strings.Count(out, "[REPRO_HIT]")
}

// countMatches counts how many lines in output reference this finding's Value or Snippet
func countMatches(out string, f *Finding) int {
	if out == "" {
		return 0
	}
	cnt := 0
	if f.Value != "" {
		cnt += strings.Count(out, f.Value)
	}
	// Match URL host if URL category
	if (strings.ToLower(f.Category) == "url" || strings.HasPrefix(f.Value, "http")) && f.Value != "" {
		host := extractHost(f.Value)
		if host != "" {
			cnt += strings.Count(out, host)
		}
	}
	// Fallback: count REPRO_HITs (means category matched, can't pin to specific value)
	if cnt == 0 {
		cnt = countReproHits(out)
	}
	return cnt
}

func extractHost(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	return s
}

// ListReproScripts returns all auto_repro_*.js available in assets/
func ListReproScripts() []string {
	cwd, _ := exec.Command("pwd").Output()
	dir := strings.TrimSpace(string(cwd))
	if dir == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "assets", "auto_repro_*.js"))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, filepath.Base(m))
	}
	return out
}
