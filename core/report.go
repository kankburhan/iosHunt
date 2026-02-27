package core

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
)

// Report represents the canonical report structure (JSON compatible)
type Report struct {
	Meta struct {
		Tool      string `json:"tool"`
		Version   string `json:"version"`
		Target    string `json:"target"`
		Timestamp string `json:"timestamp"`
	} `json:"meta"`

	AppInfo struct {
		Name     string `json:"name"`
		BundleID string `json:"bundle_id"`
		Version  string `json:"version"` // ShortVersionString
		MinOS    string `json:"min_os"`
		Binary   string `json:"binary_name"`
		TeamID   string `json:"team_id,omitempty"`
	} `json:"app_info"`

	BinaryAnalysis *BinarySecurity        `json:"binary_analysis"`
	Entitlements   map[string]interface{} `json:"entitlements"`

	Findings struct {
		Secrets           []Finding `json:"secrets"`
		URLs              []string  `json:"urls"` // URLs can remain simple for now or upgrade? Let's keep simple or upgrade later.
		Emails            []string  `json:"emails"`
		IPs               []string  `json:"ips"`
		Misconfigurations []string  `json:"misconfigurations"` // Misconfigs usually don't have file/line in same way (plist)
		Obfuscation       []string  `json:"obfuscation"`

		// Phase 15 New Categories - Upgraded to Finding in Phase 16
		Trackers        []string  `json:"trackers"`         // Trackers are usually just presence, keep as string?
		HardeningIssues []Finding `json:"hardening_issues"` // Upgraded
		Permissions     []string  `json:"permissions"`      // Plist based, keep string
		InsecureStorage []Finding `json:"insecure_storage"` // Upgraded
		CryptoIssues    []Finding `json:"crypto_issues"`    // Upgraded
		CodeIssues      []Finding `json:"code_issues"`      // Phase 18: Injection/Vulns

		// Phase 23: Deep Links
		DeepLinks struct {
			Schemes   []string `json:"schemes"`
			Universal []string `json:"universal_links"`
		} `json:"deep_links"`

		// NEW: Data Flow Analysis (Phase 24)
		DataFlows  []interface{}          `json:"data_flows,omitempty"`  // Data flow paths from source to sink
		TaintGraph map[string]interface{} `json:"taint_graph,omitempty"` // Nodes in the taint graph
	} `json:"findings"`
}

// Finding represents a vulnerability or interesting artifact with context
type Finding struct {
	Title          string   `json:"title"`
	Description    string   `json:"description,omitempty"`
	FilePath       string   `json:"file_path"`
	LineNumber     int      `json:"line_number,omitempty"`
	Snippet        string   `json:"snippet,omitempty"`
	Value          string   `json:"value,omitempty"`            // The specific secret string
	DataFlowNodeID string   `json:"dataflow_node_id,omitempty"` // NEW: Reference to TaintGraph node
	IsTaintSource  bool     `json:"is_taint_source,omitempty"`  // NEW: Is this a SOURCE?
	IsTaintSink    bool     `json:"is_taint_sink,omitempty"`    // NEW: Is this a SINK?
	TaintPaths     []string `json:"taint_paths,omitempty"`      // NEW: Path IDs flowing through this
}

func NewReport(target string) *Report {
	r := &Report{}
	r.Meta.Tool = "iOSHunt"
	r.Meta.Version = "v1.11.0"
	r.Meta.Target = target
	r.Meta.Timestamp = "TODO: Current Time" // Set time in target creation or here
	// Initialize slices to avoid null in JSON
	// Initialize slices to avoid null in JSON
	r.Findings.Secrets = []Finding{}
	r.Findings.URLs = []string{}
	r.Findings.Emails = []string{}
	r.Findings.IPs = []string{}
	r.Findings.Misconfigurations = []string{}
	r.Findings.Obfuscation = []string{}
	r.Findings.Trackers = []string{}
	r.Findings.Permissions = []string{}
	r.Findings.HardeningIssues = []Finding{}
	r.Findings.InsecureStorage = []Finding{}
	r.Findings.CryptoIssues = []Finding{}
	r.Findings.CodeIssues = []Finding{}
	return r
}

// SaveJSON saves the report to a JSON file
func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// SaveMarkdown renders the report to Markdown and saves it
func (r *Report) SaveMarkdown(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# iOSHunt Report: %s\n\n", r.AppInfo.Name)
	fmt.Fprintf(f, "**Bundle ID:** %s\n", r.AppInfo.BundleID)
	fmt.Fprintf(f, "**Min OS:** %s\n", r.AppInfo.MinOS)
	fmt.Fprintf(f, "**Binary:** %s\n", r.AppInfo.Binary)
	fmt.Fprintf(f, "\n")

	// Misconfigurations
	if len(r.Findings.Misconfigurations) > 0 {
		fmt.Fprintf(f, "## Misconfigurations & Risks\n")
		for _, m := range r.Findings.Misconfigurations {
			fmt.Fprintf(f, "- [!] %s\n", m)
		}
		fmt.Fprintf(f, "\n")
	}

	// Binary Security
	if r.BinaryAnalysis != nil {
		fmt.Fprintf(f, "## Binary Security\n")
		fmt.Fprintf(f, "- **PIE:** %v\n", r.BinaryAnalysis.PIE)
		fmt.Fprintf(f, "- **ARC:** %v\n", r.BinaryAnalysis.ARC)
		fmt.Fprintf(f, "- **Stack Canary:** %v\n", r.BinaryAnalysis.StackCanary)
		fmt.Fprintf(f, "- **Encrypted:** %v\n", r.BinaryAnalysis.Encrypted)
		fmt.Fprintf(f, "\n")
	}

	// Entitlements
	if len(r.Entitlements) > 0 {
		fmt.Fprintf(f, "## Entitlements\n")
		// Dump simple view or specific risky ones?
		// For now simple list or just risky ones were in misconfig.
		// Let's dump raw entitlements in a code block
		fmt.Fprintf(f, "```json\n")
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(r.Entitlements)
		fmt.Fprintf(f, "```\n\n")
	}

	// Secrets
	if len(r.Findings.Secrets) > 0 {
		fmt.Fprintf(f, "## Identified Secrets (%d)\n", len(r.Findings.Secrets))
		for i, s := range r.Findings.Secrets {
			if i > 50 {
				break
			}
			fmt.Fprintf(f, "- **%s** in `%s:%d`\n", s.Title, s.FilePath, s.LineNumber)
			if s.Value != "" {
				fmt.Fprintf(f, "  > **Value:** `%s`\n", s.Value)
			}
			fmt.Fprintf(f, "  > Snippet: `%s`\n", s.Snippet)
		}
		fmt.Fprintf(f, "\n")
	}

	// URLs
	if len(r.Findings.URLs) > 0 {
		fmt.Fprintf(f, "## Extracted URLs (%d)\n", len(r.Findings.URLs))
		for i, u := range r.Findings.URLs {
			if i > 50 {
				break
			}
			fmt.Fprintf(f, "- %s\n", u)
		}
		fmt.Fprintf(f, "\n")
	}

	// Permissions
	if len(r.Findings.Permissions) > 0 {
		fmt.Fprintf(f, "## Permissions\n")
		for _, p := range r.Findings.Permissions {
			fmt.Fprintf(f, "- %s\n", p)
		}
		fmt.Fprintf(f, "\n")
	}

	// Insecure Storage
	if len(r.Findings.InsecureStorage) > 0 {
		fmt.Fprintf(f, "## Insecure Storage Indicators\n")
		for _, i := range r.Findings.InsecureStorage {
			fmt.Fprintf(f, "- [!] **%s** in `%s:%d`\n", i.Title, i.FilePath, i.LineNumber)
			fmt.Fprintf(f, "  > `%s`\n", i.Snippet)
		}
		fmt.Fprintf(f, "\n")
	}

	// Code Injection / Vulnerabilities (Phase 18)
	if len(r.Findings.CodeIssues) > 0 {
		fmt.Fprintf(f, "## Code Injection & Vulnerabilities\n")
		for _, c := range r.Findings.CodeIssues {
			fmt.Fprintf(f, "- [!!!] **%s** in `%s:%d`\n", c.Title, c.FilePath, c.LineNumber)
			fmt.Fprintf(f, "  > `%s`\n", c.Snippet)
		}
		fmt.Fprintf(f, "\n")
	}

	// Crypto Issues
	if len(r.Findings.CryptoIssues) > 0 {
		fmt.Fprintf(f, "## Weak Cryptography\n")
		for _, c := range r.Findings.CryptoIssues {
			fmt.Fprintf(f, "- [!] **%s** in `%s:%d`\n", c.Title, c.FilePath, c.LineNumber)
			fmt.Fprintf(f, "  > `%s`\n", c.Snippet)
		}
		fmt.Fprintf(f, "\n")
	}

	// Hardening Issues
	if len(r.Findings.HardeningIssues) > 0 {
		fmt.Fprintf(f, "## Hardening / Security Gaps\n")
		for _, h := range r.Findings.HardeningIssues {
			fmt.Fprintf(f, "- **%s** in `%s:%d`\n", h.Title, h.FilePath, h.LineNumber)
			fmt.Fprintf(f, "  > `%s`\n", h.Snippet)
		}
		fmt.Fprintf(f, "\n")
	}

	// Trackers
	if len(r.Findings.Trackers) > 0 {
		fmt.Fprintf(f, "## Detected SDKs & Trackers\n")
		for _, t := range r.Findings.Trackers {
			fmt.Fprintf(f, "- %s\n", t)
		}
		fmt.Fprintf(f, "\n")
	}

	// Deep Links (Phase 23)
	if len(r.Findings.DeepLinks.Schemes) > 0 || len(r.Findings.DeepLinks.Universal) > 0 {
		fmt.Fprintf(f, "## Deep Links & Entry Points\n")
		if len(r.Findings.DeepLinks.Schemes) > 0 {
			fmt.Fprintf(f, "### Custom URL Schemes\n")
			for _, s := range r.Findings.DeepLinks.Schemes {
				fmt.Fprintf(f, "- `%s://`\n", s)
			}
			fmt.Fprintf(f, "\n")
		}
		if len(r.Findings.DeepLinks.Universal) > 0 {
			fmt.Fprintf(f, "### Universal Links (Associated Domains)\n")
			for _, u := range r.Findings.DeepLinks.Universal {
				fmt.Fprintf(f, "- `%s`\n", u)
			}
			fmt.Fprintf(f, "\n")
		}
	}

	return nil
}

// SaveHTML renders the report to a standalone HTML file
func (r *Report) SaveHTML(path string) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, r)
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>iOSHunt Report - {{.AppInfo.Name}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; color: #333; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        h2 { margin-top: 30px; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 5px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .info-item { background: #f9f9f9; padding: 10px; border-radius: 4px; }
        .label { font-weight: bold; color: #7f8c8d; font-size: 0.9em; }
        .value { font-size: 1.1em; }
        .finding { padding: 8px 12px; margin-bottom: 5px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 2px; }
        .finding.risk { background: #f8d7da; border-left: 4px solid #dc3545; color: #721c24; }
        .finding.critical { background: #f5c6cb; border-left: 4px solid #721c24; color: #721c24; font-weight: bold; }
        .finding.secure { background: #d4edda; border-left: 4px solid #28a745; color: #155724; }
        .code-block { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 5px 0; border-bottom: 1px solid #eee; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; margin-right: 5px; color: white; }
        .tag.true { background: #28a745; }
        .tag.false { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>iOSHunt Report</h1>
        
        <div class="info-grid">
            <div class="info-item"><div class="label">App Name</div><div class="value">{{.AppInfo.Name}}</div></div>
            <div class="info-item"><div class="label">Bundle ID</div><div class="value">{{.AppInfo.BundleID}}</div></div>
            <div class="info-item"><div class="label">Min OS</div><div class="value">{{.AppInfo.MinOS}}</div></div>
            <div class="info-item"><div class="label">Binary</div><div class="value">{{.AppInfo.Binary}}</div></div>
            <div class="info-item"><div class="label">Tool Version</div><div class="value">{{.Meta.Version}}</div></div>
        </div>

        <h2>Binary Security</h2>
        <div class="info-grid">
            {{if .BinaryAnalysis}}
            <div class="info-item"><div class="label">PIE</div><div class="value"><span class="tag {{.BinaryAnalysis.PIE}}">{{.BinaryAnalysis.PIE}}</span></div></div>
            <div class="info-item"><div class="label">ARC</div><div class="value"><span class="tag {{.BinaryAnalysis.ARC}}">{{.BinaryAnalysis.ARC}}</span></div></div>
            <div class="info-item"><div class="label">Stack Canary</div><div class="value"><span class="tag {{.BinaryAnalysis.StackCanary}}">{{.BinaryAnalysis.StackCanary}}</span></div></div>
            <div class="info-item"><div class="label">Encrypted</div><div class="value"><span class="tag {{.BinaryAnalysis.Encrypted}}">{{.BinaryAnalysis.Encrypted}}</span></div></div>
            {{end}}
        </div>

        {{if .Findings.Misconfigurations}}
        <h2>Misconfigurations & Risks</h2>
        {{range .Findings.Misconfigurations}}
            <div class="finding risk">{{.}}</div>
        {{end}}
        {{end}}

        {{if .Findings.Secrets}}
        <h2>Identified Secrets ({{len .Findings.Secrets}})</h2>
        <ul>
            {{range .Findings.Secrets}}
            <li>
                <strong>{{.Title}}</strong> in <code>{{.FilePath}}:{{.LineNumber}}</code><br>
                <div class="code-block" style="padding:5px; margin-top:5px; font-size:0.9em;">{{.Snippet}}</div>
            </li>
            {{end}}
        </ul>
        {{end}}
        
        {{if .Entitlements}}
        <h2>Entitlements</h2>
        <div class="code-block"><pre>{{.Entitlements | printf "%+v"}}</pre></div>
        {{end}}

        {{if .Findings.URLs}}
        <h2>URLs ({{len .Findings.URLs}})</h2>
        <div style="max-height: 300px; overflow-y: auto;">
            <ul>
                {{range .Findings.URLs}}
                <li><a href="{{.}}">{{.}}</a></li>
                {{end}}
            </ul>
        </div>
        {{end}}

        <!-- Phase 15 Sections -->
        
        {{if .Findings.Permissions}}
        <h2>Permissions</h2>
        <ul>
            {{range .Findings.Permissions}}
            <li>{{.}}</li>
            {{end}}
        </ul>
        {{end}}

        {{if .Findings.InsecureStorage}}
        <h2>Insecure Storage Indicators</h2>
        {{range .Findings.InsecureStorage}}
            <div class="finding risk">
                <strong>{{.Title}}</strong> - {{.FilePath}}:{{.LineNumber}}<br>
                <code style="display:block; margin-top:5px; color:#555;">{{.Snippet}}</code>
            </div>
        {{end}}
        {{end}}

        {{if .Findings.CodeIssues}}
        <h2>Code Injection & Vulnerabilities</h2>
        {{range .Findings.CodeIssues}}
            <div class="finding critical">
                <strong>{{.Title}}</strong> - {{.FilePath}}:{{.LineNumber}}<br>
                <code style="display:block; margin-top:5px; color:#555;">{{.Snippet}}</code>
            </div>
        {{end}}
        {{end}}

        {{if .Findings.CryptoIssues}}
        <h2>Weak Cryptography</h2>
        {{range .Findings.CryptoIssues}}
            <div class="finding risk">
                <strong>{{.Title}}</strong> - {{.FilePath}}:{{.LineNumber}}<br>
                <code style="display:block; margin-top:5px; color:#555;">{{.Snippet}}</code>
            </div>
        {{end}}
        {{end}}

        {{if .Findings.HardeningIssues}}
        <h2>Hardening & Security Gaps</h2>
        {{range .Findings.HardeningIssues}}
            <div class="finding">
                <strong>{{.Title}}</strong> - {{.FilePath}}:{{.LineNumber}}<br>
                <code style="display:block; margin-top:5px; color:#555;">{{.Snippet}}</code>
            </div>
        {{end}}
        {{end}}

        {{if .Findings.Trackers}}
        <h2>Detected SDKs & Trackers</h2>
        <ul>
            {{range .Findings.Trackers}}
            <li><span class="tag false">{{.}}</span></li>
            {{end}}
        </ul>
        {{end}}

    </div>
</body>
</html>
`
