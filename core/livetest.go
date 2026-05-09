package core

// Live exploit verification engine.
//
// Performs ACTIVE probes against findings to confirm exploitability:
//   - Validates API keys by hitting real provider endpoints
//   - Probes URLs for accessibility / open endpoints / missing auth
//   - Verifies ATS bypass by attempting plaintext HTTP fetches
//   - Tests endpoint reachability with timeout
//
// All probes are TIMED-OUT, idempotent, and save raw responses as evidence.
// This is ACTIVE TESTING — only run against targets you are authorized to test.

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// LiveTester executes live verification probes
type LiveTester struct {
	Client    *http.Client
	OutputDir string
	UserAgent string
	DryRun    bool // if true, only print what would be done
}

// NewLiveTester returns a tester with sane defaults
func NewLiveTester(outputDir string) *LiveTester {
	if outputDir == "" {
		outputDir = "./reports/livetest"
	}
	_ = os.MkdirAll(outputDir, 0755)
	return &LiveTester{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		OutputDir: outputDir,
		UserAgent: "iOSHunt-LiveTest/1.0 (authorized-pentest)",
	}
}

// LiveResult is the outcome of a single probe
type LiveResult struct {
	FindingID string `json:"finding_id"`
	Provider  string `json:"provider,omitempty"`
	Status    string `json:"status"` // CONFIRMED / FAILED / UNREACHABLE / SKIPPED
	HTTPCode  int    `json:"http_code,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence_path,omitempty"`
	ProbedAt  string `json:"probed_at"`
}

// VerifyAll runs live probes for every finding that supports verification.
// Returns updated findings with LiveStatus / LiveVerified / Evidence populated.
func (lt *LiveTester) VerifyAll(findings []*Finding) []LiveResult {
	results := make([]LiveResult, 0, len(findings))
	for _, f := range findings {
		if f.ID == "" {
			f.ID = ComputeFindingID(f)
		}
		r := lt.VerifyFinding(f)
		results = append(results, r)

		// Populate finding fields back
		f.LiveStatus = r.Status
		f.LiveVerified = r.Status == "CONFIRMED"
		f.LiveDetails = r.Detail
		f.LiveProbedAt = r.ProbedAt
		if r.Evidence != "" {
			f.Evidence = append(f.Evidence, Evidence{
				Type:        "curl_output",
				Path:        r.Evidence,
				Description: fmt.Sprintf("Live probe (%s) — %s", r.Provider, r.Status),
				CapturedAt:  r.ProbedAt,
			})
		}
	}
	return results
}

// VerifyFinding routes the finding to the correct prober
func (lt *LiveTester) VerifyFinding(f *Finding) LiveResult {
	now := time.Now().UTC().Format(time.RFC3339)
	res := LiveResult{
		FindingID: f.ID,
		Status:    "SKIPPED",
		Detail:    "no live verification available for this finding type",
		ProbedAt:  now,
	}

	if lt.DryRun {
		res.Status = "SKIPPED"
		res.Detail = "dry-run mode"
		return res
	}

	value := strings.TrimSpace(f.Value)
	title := strings.ToLower(f.Title)
	cat := strings.ToLower(f.Category)

	// 1. API Key probes
	if value != "" {
		if provider := DetectAPIKeyProvider(value, f.Snippet); provider != "" {
			return lt.probeAPIKey(f, provider, value)
		}
	}

	// 2. URL probes (URL findings & insecure URLs)
	if cat == "url" || strings.Contains(title, "url") || strings.HasPrefix(value, "http") {
		target := value
		if target == "" {
			target = extractFirstURL(f.Snippet)
		}
		if target != "" {
			return lt.probeURL(f, target)
		}
	}

	// 3. ATS bypass — try fetching HTTP plaintext
	if strings.Contains(title, "ats") || strings.Contains(title, "arbitrary load") {
		if u := extractFirstURL(f.Snippet); u != "" {
			httpURL := strings.Replace(u, "https://", "http://", 1)
			res2 := lt.probeURL(f, httpURL)
			if res2.HTTPCode > 0 {
				res2.Provider = "ats-bypass"
				res2.Detail = "HTTP plaintext is reachable — ATS bypass effective. " + res2.Detail
			}
			return res2
		}
	}

	return res
}

// probeAPIKey hits the real provider auth endpoint to confirm validity.
func (lt *LiveTester) probeAPIKey(f *Finding, provider, key string) LiveResult {
	now := time.Now().UTC().Format(time.RFC3339)
	res := LiveResult{
		FindingID: f.ID,
		Provider:  provider,
		Status:    "FAILED",
		ProbedAt:  now,
	}

	probe := apiKeyProbeFor(provider, key)
	if probe == nil {
		res.Status = "SKIPPED"
		res.Detail = fmt.Sprintf("provider %q known but no live probe configured", provider)
		return res
	}

	req, err := http.NewRequest(probe.Method, probe.URL, nil)
	if err != nil {
		res.Detail = "request build failed: " + err.Error()
		return res
	}
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", lt.UserAgent)

	resp, err := lt.Client.Do(req)
	if err != nil {
		res.Status = "UNREACHABLE"
		res.Detail = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	res.HTTPCode = resp.StatusCode
	res.Detail = fmt.Sprintf("HTTP %d — %s", resp.StatusCode, snippet(string(body), 200))

	if probe.IsValid(resp.StatusCode, string(body)) {
		res.Status = "CONFIRMED"
		res.Detail = fmt.Sprintf("CONFIRMED LIVE %s key — HTTP %d. %s", provider, resp.StatusCode, res.Detail)
	}

	res.Evidence = lt.saveEvidence(f.ID, provider, probe.URL, resp.StatusCode, body)
	return res
}

// probeURL performs a HEAD then GET to assess a URL
func (lt *LiveTester) probeURL(f *Finding, target string) LiveResult {
	now := time.Now().UTC().Format(time.RFC3339)
	res := LiveResult{
		FindingID: f.ID,
		Provider:  "url-probe",
		Status:    "UNREACHABLE",
		ProbedAt:  now,
	}

	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		res.Status = "SKIPPED"
		res.Detail = "non-http(s) URL or unparseable: " + target
		return res
	}

	// HEAD first
	req, _ := http.NewRequest("HEAD", target, nil)
	req.Header.Set("User-Agent", lt.UserAgent)
	resp, err := lt.Client.Do(req)
	if err != nil {
		res.Detail = "HEAD failed: " + err.Error()
		return res
	}
	resp.Body.Close()

	res.HTTPCode = resp.StatusCode
	res.Detail = fmt.Sprintf("HEAD %s -> %d", target, resp.StatusCode)

	// Classify
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Open endpoint — possible auth missing
		// GET small body for evidence
		req2, _ := http.NewRequest("GET", target, nil)
		req2.Header.Set("User-Agent", lt.UserAgent)
		resp2, err2 := lt.Client.Do(req2)
		if err2 == nil {
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
			resp2.Body.Close()
			res.Status = "CONFIRMED"
			res.Detail = fmt.Sprintf("CONFIRMED REACHABLE — HTTP %d, body sample: %s", resp2.StatusCode, snippet(string(body), 200))
			res.Evidence = lt.saveEvidence(f.ID, "url-probe", target, resp2.StatusCode, body)
			if looksLikeOpenAdmin(target, string(body)) {
				res.Detail = "[!] OPEN ADMIN/SENSITIVE ENDPOINT — " + res.Detail
			}
		}
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		res.Status = "CONFIRMED"
		res.Detail = fmt.Sprintf("CONFIRMED REACHABLE (auth-protected) — HTTP %d", resp.StatusCode)
	case resp.StatusCode >= 500:
		res.Status = "CONFIRMED"
		res.Detail = fmt.Sprintf("CONFIRMED REACHABLE (server error) — HTTP %d", resp.StatusCode)
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		res.Status = "FAILED"
		res.Detail = fmt.Sprintf("endpoint not found — HTTP %d", resp.StatusCode)
	}
	return res
}

// saveEvidence writes the raw probe response to disk and returns the path
func (lt *LiveTester) saveEvidence(findingID, provider, target string, code int, body []byte) string {
	if lt.OutputDir == "" {
		return ""
	}
	safeTarget := safeFilename(target)
	if len(safeTarget) > 50 {
		safeTarget = safeTarget[:50]
	}
	name := fmt.Sprintf("%s_%s_%s_%d.txt", provider, findingID[:8], safeTarget, code)
	path := filepath.Join(lt.OutputDir, name)
	header := fmt.Sprintf("# %s probe -> HTTP %d\n# target: %s\n# captured: %s\n\n", provider, code, target, time.Now().UTC().Format(time.RFC3339))
	_ = os.WriteFile(path, append([]byte(header), body...), 0644)
	return path
}

// SaveResults writes all probe results to <outputDir>/livetest_results.json
func (lt *LiveTester) SaveResults(results []LiveResult) (string, error) {
	if lt.OutputDir == "" {
		return "", fmt.Errorf("no output dir")
	}
	path := filepath.Join(lt.OutputDir, "livetest_results.json")
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ----------------- Provider probe registry -----------------

type apiProbe struct {
	Method  string
	URL     string
	Headers map[string]string
	IsValid func(code int, body string) bool
}

func apiKeyProbeFor(provider, key string) *apiProbe {
	switch provider {
	case "google":
		// Geocoding API key validation (no quota burn for invalid keys)
		return &apiProbe{
			Method: "GET",
			URL:    "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=" + url.QueryEscape(key),
			IsValid: func(code int, body string) bool {
				return code == 200 && !strings.Contains(body, "REQUEST_DENIED") && !strings.Contains(body, "INVALID_REQUEST")
			},
		}
	case "stripe":
		return &apiProbe{
			Method: "GET",
			URL:    "https://api.stripe.com/v1/charges?limit=1",
			Headers: map[string]string{
				"Authorization": "Bearer " + key,
			},
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"object":`)
			},
		}
	case "github":
		return &apiProbe{
			Method: "GET",
			URL:    "https://api.github.com/user",
			Headers: map[string]string{
				"Authorization": "Bearer " + key,
				"Accept":        "application/vnd.github+json",
			},
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"login":`)
			},
		}
	case "slack":
		return &apiProbe{
			Method: "POST",
			URL:    "https://slack.com/api/auth.test",
			Headers: map[string]string{
				"Authorization": "Bearer " + key,
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"ok":true`)
			},
		}
	case "mapbox":
		return &apiProbe{
			Method: "GET",
			URL:    "https://api.mapbox.com/tokens/v2?access_token=" + url.QueryEscape(key),
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"token":`)
			},
		}
	case "sendgrid":
		return &apiProbe{
			Method: "GET",
			URL:    "https://api.sendgrid.com/v3/user/profile",
			Headers: map[string]string{
				"Authorization": "Bearer " + key,
			},
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"email":`)
			},
		}
	case "twilio":
		// Twilio uses Basic auth with SID:TOKEN — we only have the token usually.
		// We cannot validate without SID. Return nil to mark SKIPPED.
		return nil
	case "firebase":
		// Firebase API keys aren't auth — they're project IDs. Probe firestore default rules
		return &apiProbe{
			Method: "GET",
			URL:    "https://firebase.googleapis.com/v1beta1/availableProjects?key=" + url.QueryEscape(key),
			IsValid: func(code int, body string) bool {
				return code == 200
			},
		}
	case "openai":
		return &apiProbe{
			Method: "GET",
			URL:    "https://api.openai.com/v1/models",
			Headers: map[string]string{
				"Authorization": "Bearer " + key,
			},
			IsValid: func(code int, body string) bool {
				return code == 200 && strings.Contains(body, `"id":`)
			},
		}
	case "aws":
		// AWS Access Key needs paired secret + signing — too complex for a quick probe.
		// Best-effort: hit STS with no signature, expect 403 SignatureMissing not InvalidClientTokenId
		return nil
	}
	return nil
}

// DetectAPIKeyProvider classifies an API key by its format / surrounding context.
// Returns "" if no provider matches with confidence.
func DetectAPIKeyProvider(value, context string) string {
	v := value
	c := strings.ToLower(context + " " + value)

	// Format-based (high confidence)
	switch {
	case regexp.MustCompile(`^AIza[0-9A-Za-z\-_]{35}$`).MatchString(v):
		return "google"
	case strings.HasPrefix(v, "sk_live_") || strings.HasPrefix(v, "sk_test_") || strings.HasPrefix(v, "pk_live_") || strings.HasPrefix(v, "pk_test_"):
		return "stripe"
	case regexp.MustCompile(`^ghp_[A-Za-z0-9]{36,}$`).MatchString(v) || regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{50,}$`).MatchString(v):
		return "github"
	case strings.HasPrefix(v, "xoxb-") || strings.HasPrefix(v, "xoxp-") || strings.HasPrefix(v, "xoxa-"):
		return "slack"
	case strings.HasPrefix(v, "pk.") && len(v) > 60:
		return "mapbox"
	case strings.HasPrefix(v, "SG.") && strings.Contains(v, "."):
		return "sendgrid"
	case strings.HasPrefix(v, "sk-") && len(v) > 30:
		return "openai"
	case regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`).MatchString(v):
		return "aws"
	case strings.HasPrefix(v, "AC") && len(v) == 34:
		return "twilio"
	}

	// Context-based hints (lower confidence)
	switch {
	case strings.Contains(c, "firebase") && strings.HasPrefix(v, "AIza"):
		return "firebase"
	case strings.Contains(c, "openai"):
		return "openai"
	}

	return ""
}

// ----------------- helpers -----------------

func extractFirstURL(s string) string {
	re := regexp.MustCompile(`https?://[^\s"'<>)]+`)
	return re.FindString(s)
}

func looksLikeOpenAdmin(target, body string) bool {
	low := strings.ToLower(target)
	bl := strings.ToLower(body)
	hits := []string{"/admin", "/dashboard", "/internal", "/debug", "/.env", "swagger", "openapi"}
	for _, h := range hits {
		if strings.Contains(low, h) {
			return true
		}
	}
	return strings.Contains(bl, "<title>swagger") || strings.Contains(bl, "phpmyadmin")
}

func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func safeFilename(s string) string {
	s = strings.ReplaceAll(s, "://", "_")
	s = regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(s, "_")
	return s
}

// ComputeFindingID returns a stable short ID for a finding.
func ComputeFindingID(f *Finding) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%d|%s", f.Title, f.FilePath, f.LineNumber, f.Value)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
