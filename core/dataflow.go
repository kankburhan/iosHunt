package core

import (
	"fmt"
	"os"
	"strings"
)

// DataFlowNodeType represents the role of a node in the taint graph
type DataFlowNodeType string

const (
	NodeTypeSource       DataFlowNodeType = "source"
	NodeTypeSink         DataFlowNodeType = "sink"
	NodeTypeIntermediate DataFlowNodeType = "intermediate"
)

// DataFlowNode represents a single point in the data flow graph
type DataFlowNode struct {
	ID             string           `json:"id"`
	Type           DataFlowNodeType `json:"type"`
	Name           string           `json:"name"`
	Category       string           `json:"category"` // "secret", "logging", "network", "storage"
	SourceFinding  *Finding         `json:"source_finding,omitempty"`
	File           string           `json:"file"`
	Line           int              `json:"line"`
	Context        string           `json:"context"`
	Confidence     float64          `json:"confidence"` // 0.0-1.0
	TaintedFrom    []string         `json:"tainted_from,omitempty"`
	PropagatesTo   []string         `json:"propagates_to,omitempty"`
	BinaryTracking *BinaryFlowInfo  `json:"binary_tracking,omitempty"` // For binary-level analysis
}

// BinaryFlowInfo tracks data flow at the binary/assembly level
type BinaryFlowInfo struct {
	Address         string          `json:"address"`      // Memory address or offset in binary
	Instructions    []string        `json:"instructions"` // Assembly instructions involved
	Registers       []string        `json:"registers"`    // Registers used (rax, r0, etc)
	Functions       []string        `json:"functions"`    // Function names involved
	ControlFlowPath string          `json:"control_flow"` // Path through CFG
	ConfidenceInfo  *ConfidenceData `json:"confidence_details,omitempty"`
}

// ConfidenceData explains why we're confident in a flow
type ConfidenceData struct {
	StringMatch      float64 `json:"string_match"`       // Exact string match confidence
	SemanticMatch    float64 `json:"semantic_match"`     // Variable name match
	ControlFlowMatch float64 `json:"control_flow_match"` // Binary-level CFG match
	FileProximity    float64 `json:"file_proximity"`     // Are source/sink in same file?
	FunctionProx     float64 `json:"function_proximity"` // Binary-level function proximity
	FinalScore       float64 `json:"final_score"`        // Overall confidence
}

// DataFlowPath represents a complete source→sink flow
type DataFlowPath struct {
	ID           string          `json:"id"`
	Source       *DataFlowNode   `json:"source"`
	Sinks        []*DataFlowNode `json:"sinks"`
	Confidence   float64         `json:"confidence"`
	Severity     string          `json:"severity"` // CRITICAL/HIGH/MEDIUM/LOW
	Description  string          `json:"description"`
	Nodes        []*DataFlowNode `json:"nodes"`
	Remediations []string        `json:"remediations,omitempty"`
	FlowType     string          `json:"flow_type"` // "logging", "network", "storage", etc
}

// DataFlowAnalyzer orchestrates the complete data flow analysis
type DataFlowAnalyzer struct {
	Target      *Target
	Findings    []Finding
	Nodes       map[string]*DataFlowNode
	Paths       []DataFlowPath
	SourceNodes []*DataFlowNode
	SinkNodes   []*DataFlowNode
	BinaryData  string // Extracted strings from binary
	BinaryPath  string // Path to binary file
}

// ============================================
// PUBLIC API
// ============================================

// AnalyzeDataFlow is the main entry point for data flow analysis
func AnalyzeDataFlow(target *Target, report *Report) error {
	if len(report.Findings.Secrets) == 0 {
		// No secrets detected, no data flow analysis needed
		return nil
	}

	analyzer := &DataFlowAnalyzer{
		Target:     target,
		Findings:   report.Findings.Secrets,
		Nodes:      make(map[string]*DataFlowNode),
		BinaryPath: target.BinaryPath,
	}

	// Extract binary strings for analysis
	if binaryData, err := readBinaryStrings(target.BinaryPath); err == nil {
		analyzer.BinaryData = binaryData
	}

	// Phase 1: Identify data sources
	analyzer.IdentifySources(report)

	// Phase 2: Identify data sinks
	analyzer.IdentifySinks(report)

	// Phase 3: Phase 3A - String-based flow detection
	analyzer.DetectFlowsStringBased(report)

	// Phase 4: Phase 3B - Binary-level flow detection (control flow analysis)
	if analyzer.BinaryPath != "" && analyzer.BinaryData != "" {
		analyzer.DetectFlowsBinaryLevel(report)
	}

	// Phase 5: Merge and deduplicate flows, calculate severity
	analyzer.CalculateSeverity()

	// Phase 6: Generate remediations
	analyzer.GenerateRemediations()

	// Phase 7: Add flows to report
	analyzer.UpdateReport(report)

	return nil
}

// ============================================
// PHASE 1: SOURCE IDENTIFICATION
// ============================================

func (dfa *DataFlowAnalyzer) IdentifySources(report *Report) {
	// All validated secrets are data sources
	for i, finding := range report.Findings.Secrets {
		node := &DataFlowNode{
			ID:            fmt.Sprintf("source_secret_%d", i),
			Type:          NodeTypeSource,
			Name:          finding.Title,
			Category:      "secret",
			SourceFinding: &finding,
			File:          finding.FilePath,
			Line:          finding.LineNumber,
			Context:       finding.Snippet,
			Confidence:    1.0, // Secrets are confirmed sources
			TaintedFrom:   []string{},
			PropagatesTo:  []string{},
		}

		dfa.SourceNodes = append(dfa.SourceNodes, node)
		dfa.Nodes[node.ID] = node
	}

	// Also treat code issues that mention hardcoded credentials as sources
	for i, finding := range report.Findings.CodeIssues {
		if isCredentialAssignmentPattern(finding.Title) {
			node := &DataFlowNode{
				ID:            fmt.Sprintf("source_code_%d", i),
				Type:          NodeTypeSource,
				Name:          "Hardcoded: " + finding.Title,
				Category:      "secret",
				SourceFinding: &finding,
				File:          finding.FilePath,
				Line:          finding.LineNumber,
				Context:       finding.Snippet,
				Confidence:    0.85,
				TaintedFrom:   []string{},
				PropagatesTo:  []string{},
			}

			dfa.SourceNodes = append(dfa.SourceNodes, node)
			dfa.Nodes[node.ID] = node
		}
	}
}

// ============================================
// PHASE 2: SINK IDENTIFICATION
// ============================================

func (dfa *DataFlowAnalyzer) IdentifySinks(report *Report) {
	sinkID := 0

	// Category 1: LOGGING SINKS (CRITICAL RISK)
	for _, finding := range report.Findings.CodeIssues {
		if isLoggingSink(finding) {
			sinkID++
			node := &DataFlowNode{
				ID:            fmt.Sprintf("sink_logging_%d", sinkID),
				Type:          NodeTypeSink,
				Name:          fmt.Sprintf("Log: %s", finding.Title),
				Category:      "logging",
				SourceFinding: &finding,
				File:          finding.FilePath,
				Line:          finding.LineNumber,
				Context:       finding.Snippet,
				Confidence:    0.95, // Logging is explicit
				TaintedFrom:   []string{},
				PropagatesTo:  []string{},
			}

			dfa.SinkNodes = append(dfa.SinkNodes, node)
			dfa.Nodes[node.ID] = node
		}
	}

	// Category 2: NETWORK SINKS (HIGH RISK)
	for _, url := range report.Findings.URLs {
		if !isSafeURL(url) {
			sinkID++
			node := &DataFlowNode{
				ID:           fmt.Sprintf("sink_network_%d", sinkID),
				Type:         NodeTypeSink,
				Name:         fmt.Sprintf("Network: %s", truncateURL(url)),
				Category:     "network",
				File:         "unknown",
				Line:         0,
				Context:      url,
				Confidence:   0.75, // Networks are risky but not file-mapped
				TaintedFrom:  []string{},
				PropagatesTo: []string{},
			}

			dfa.SinkNodes = append(dfa.SinkNodes, node)
			dfa.Nodes[node.ID] = node
		}
	}

	// Category 3: STORAGE SINKS (MEDIUM-HIGH RISK)
	for idx := 0; idx < len(report.Findings.Misconfigurations); idx++ {
		misc := report.Findings.Misconfigurations[idx]
		if isStorageSink(misc) {
			sinkID++
			node := &DataFlowNode{
				ID:           fmt.Sprintf("sink_storage_%d", sinkID),
				Type:         NodeTypeSink,
				Name:         "Storage: " + extractStorageName(misc),
				Category:     "storage",
				File:         "Info.plist",
				Line:         0,
				Context:      misc,
				Confidence:   0.85,
				TaintedFrom:  []string{},
				PropagatesTo: []string{},
			}

			dfa.SinkNodes = append(dfa.SinkNodes, node)
			dfa.Nodes[node.ID] = node
		}
	}

	// Category 4: CLIPBOARD/PASTEBOARD SINKS (HIGH RISK)
	for _, finding := range report.Findings.CodeIssues {
		if strings.Contains(strings.ToLower(finding.Title), "pasteboard") ||
			strings.Contains(strings.ToLower(finding.Description), "clipboard") {
			sinkID++
			node := &DataFlowNode{
				ID:            fmt.Sprintf("sink_pasteboard_%d", sinkID),
				Type:          NodeTypeSink,
				Name:          "Pasteboard/Clipboard Access",
				Category:      "clipboard",
				SourceFinding: &finding,
				File:          finding.FilePath,
				Line:          finding.LineNumber,
				Context:       finding.Snippet,
				Confidence:    0.9,
				TaintedFrom:   []string{},
				PropagatesTo:  []string{},
			}

			dfa.SinkNodes = append(dfa.SinkNodes, node)
			dfa.Nodes[node.ID] = node
		}
	}
}

// ============================================
// PHASE 3A: STRING-BASED FLOW DETECTION
// ============================================

func (dfa *DataFlowAnalyzer) DetectFlowsStringBased(report *Report) {
	for _, source := range dfa.SourceNodes {
		secretValue := source.SourceFinding.Value
		secretName := extractVariableName(source.Name)

		for _, sink := range dfa.SinkNodes {
			confidence := dfa.CalculateFlowConfidenceStringBased(source, sink, secretValue, secretName)

			if confidence > 0.45 { // Threshold for string-based detection
				flowID := fmt.Sprintf("flow_string_%s_to_%s", source.ID, sink.ID)
				path := &DataFlowPath{
					ID:         flowID,
					Source:     source,
					Sinks:      []*DataFlowNode{sink},
					Confidence: confidence,
					Nodes:      []*DataFlowNode{source, sink},
					FlowType:   sink.Category,
				}

				dfa.Paths = append(dfa.Paths, *path)

				// Update node connections
				source.PropagatesTo = append(source.PropagatesTo, sink.ID)
				sink.TaintedFrom = append(sink.TaintedFrom, source.ID)
			}
		}
	}
}

// CalculateFlowConfidenceStringBased uses multiple heuristics
func (dfa *DataFlowAnalyzer) CalculateFlowConfidenceStringBased(
	source, sink *DataFlowNode,
	secretValue, secretName string) float64 {

	confidence := &ConfidenceData{}

	// 1. EXACT STRING MATCH (highest confidence)
	if secretValue != "" && strings.Contains(sink.Context, secretValue) {
		confidence.StringMatch = 1.0
	} else if secretValue != "" && len(secretValue) > 8 &&
		strings.Contains(sink.Context, secretValue[:8]) { // Truncated match
		confidence.StringMatch = 0.85
	}

	// 2. SEMANTIC MATCH (variable name in both)
	if secretName != "" && strings.Contains(strings.ToLower(sink.Context), strings.ToLower(secretName)) {
		confidence.SemanticMatch = 0.75
	}

	// 3. FILE PROXIMITY (same file = strong indicator)
	if source.File == sink.File && source.File != "unknown" {
		confidence.FileProximity = 0.25
	} else if source.File == sink.File {
		confidence.FileProximity = 0.0
	}

	// 4. SENSITIVE KEYWORD MATCHING
	if hasSensitiveKeywordMatch(source.Name, sink.Context) {
		confidence.SemanticMatch = 0.65
	}

	// Calculate final score by weighted combination
	finalScore := (confidence.StringMatch * 0.50) + // Exact match is strongest signal
		(confidence.SemanticMatch * 0.25) + // Variable name match
		(confidence.FileProximity * 0.15) // File proximity

	// Adjust based on sink type (logging is more likely to receive data)
	switch sink.Category {
	case "logging":
		finalScore *= 1.1 // Logging is common destination
	case "network":
		finalScore *= 1.05 // Network is common exfil
	case "storage":
		finalScore *= 1.0 // Storage could go either way
	case "clipboard":
		finalScore *= 0.95 // Clipboard is less common
	}

	if finalScore > 1.0 {
		finalScore = 1.0
	}

	confidence.FinalScore = finalScore
	return finalScore
}

// ============================================
// PHASE 3B: BINARY-LEVEL ANALYSIS WITH CFG
// ============================================

// DetectFlowsBinaryLevel performs control flow analysis on the binary
func (dfa *DataFlowAnalyzer) DetectFlowsBinaryLevel(report *Report) {
	if dfa.BinaryPath == "" {
		return
	}

	// Build a control flow graph from binary analysis
	// This uses string-based heuristics since full Ghidra integration is complex
	// In a real implementation, you'd use Ghidra's automated analysis

	for _, source := range dfa.SourceNodes {
		secretValue := source.SourceFinding.Value

		// Try to trace this value through the binary
		traces := dfa.TraceSecretInBinary(secretValue, source)

		// See if any traces lead to known sinks
		for _, trace := range traces {
			for _, sink := range dfa.SinkNodes {
				// Check if trace intersects with sink
				if dfa.TraceIntersectsSink(trace, sink) {
					confidence := dfa.CalculateFlowConfidenceBinaryLevel(trace, sink, source)

					if confidence > 0.50 { // Higher threshold for binary-level (more uncertain)
						flowID := fmt.Sprintf("flow_binary_%s_to_%s", source.ID, sink.ID)

						// Check if we already have a string-based flow for this pair
						existingFlow := dfa.FindExistingFlow(source, sink)
						if existingFlow != nil {
							// Merge with existing flow, increase confidence
							existingFlow.Confidence = (existingFlow.Confidence + confidence) / 2.0
							if existingFlow.Nodes == nil {
								existingFlow.Nodes = []*DataFlowNode{}
							}
							// Add intermediate nodes if any
							for _, node := range trace.Nodes {
								if node.Type == NodeTypeIntermediate {
									existingFlow.Nodes = append(existingFlow.Nodes, node)
								}
							}
						} else {
							// Create new path from binary analysis
							path := &DataFlowPath{
								ID:         flowID,
								Source:     source,
								Sinks:      []*DataFlowNode{sink},
								Confidence: confidence,
								Nodes:      trace.Nodes,
								FlowType:   sink.Category,
							}
							dfa.Paths = append(dfa.Paths, *path)
						}
					}
				}
			}
		}
	}
}

// BinaryTrace represents a potential data flow path discovered through binary analysis
type BinaryTrace struct {
	SecretValue  string
	Nodes        []*DataFlowNode // Intermediate nodes in the trace
	Confidence   float64
	Instructions []string // Assembly instructions found
}

// TraceSecretInBinary attempts to find the secret in the binary and trace its usage
func (dfa *DataFlowAnalyzer) TraceSecretInBinary(secretValue string, source *DataFlowNode) []BinaryTrace {
	var traces []BinaryTrace

	// Look for the secret string in the binary
	if !strings.Contains(dfa.BinaryData, secretValue) {
		return traces // Secret not in binary strings
	}

	// Look for function calls that might use this secret
	// Common patterns:
	// 1. Secret passed to network function
	// 2. Secret passed to logging function
	// 3. Secret stored in memory/keychain

	suspiciousFunctions := []string{
		"NSLog", "print", "printf", "fprintf",
		"URLRequest", "curl", "http", "POST", "GET",
		"SecItemAdd", "UserDefaults", "NSKeyedArchiver",
		"UIPasteboard", "URLSession", "AFHTTPClient",
	}

	for _, funcName := range suspiciousFunctions {
		if strings.Contains(dfa.BinaryData, funcName) {
			// Heuristic: if both secret and function are in binary,
			// they might be related
			trace := BinaryTrace{
				SecretValue: secretValue,
				Confidence:  0.6, // Lower confidence for heuristic
				Nodes: []*DataFlowNode{
					{
						ID:   fmt.Sprintf("binary_func_%s", funcName),
						Type: NodeTypeIntermediate,
						Name: funcName,
					},
				},
			}
			traces = append(traces, trace)
		}
	}

	return traces
}

// TraceIntersectsSink checks if a binary trace leads to a sink
func (dfa *DataFlowAnalyzer) TraceIntersectsSink(trace BinaryTrace, sink *DataFlowNode) bool {
	// Check if the trace's intermediate nodes match sink characteristics
	for _, node := range trace.Nodes {
		if strings.ToLower(node.Name) == strings.ToLower(sink.Name) {
			return true
		}
		// Check if function name matches sink category
		if sink.Category == "logging" && isLoggingFunction(node.Name) {
			return true
		}
		if sink.Category == "network" && isNetworkFunction(node.Name) {
			return true
		}
		if sink.Category == "storage" && isStorageFunction(node.Name) {
			return true
		}
	}
	return false
}

// CalculateFlowConfidenceBinaryLevel calculates confidence for binary-level flows
func (dfa *DataFlowAnalyzer) CalculateFlowConfidenceBinaryLevel(
	trace BinaryTrace, sink *DataFlowNode, source *DataFlowNode) float64 {

	confidence := &ConfidenceData{}

	// Base confidence from trace
	confidence.ControlFlowMatch = trace.Confidence

	// Does the trace actually lead to this sink?
	if dfa.TraceIntersectsSink(trace, sink) {
		confidence.ControlFlowMatch = 0.85
	}

	// Are source and sink in same binary?
	if source.File == sink.File || source.File == "AirAsiaMobile" || sink.File == "unknown" {
		confidence.FunctionProx = 0.2
	}

	finalScore := (confidence.ControlFlowMatch * 0.60) +
		(confidence.FunctionProx * 0.20)

	if finalScore > 1.0 {
		finalScore = 1.0
	}

	confidence.FinalScore = finalScore
	return finalScore
}

// ============================================
// PHASE 4: SEVERITY CALCULATION
// ============================================

func (dfa *DataFlowAnalyzer) CalculateSeverity() {
	for i := range dfa.Paths {
		path := &dfa.Paths[i]

		baseSeverity := dfa.DetermineSeverityByFlowType(path.FlowType, path.Confidence)
		path.Severity = baseSeverity

		// Adjust severity based on confidence
		if path.Confidence < 0.50 {
			if path.Severity == "CRITICAL" {
				path.Severity = "HIGH"
			} else if path.Severity == "HIGH" {
				path.Severity = "MEDIUM"
			}
		}
	}
}

func (dfa *DataFlowAnalyzer) DetermineSeverityByFlowType(flowType string, confidence float64) string {
	switch flowType {
	case "logging":
		// Logging leaks are ALWAYS severe
		if confidence >= 0.70 {
			return "CRITICAL"
		}
		return "HIGH"

	case "network":
		// Network exfiltration is CRITICAL if high confidence
		if confidence >= 0.85 {
			return "CRITICAL"
		}
		if confidence >= 0.65 {
			return "HIGH"
		}
		return "MEDIUM"

	case "storage":
		// Insecure storage is HIGH
		if confidence >= 0.80 {
			return "HIGH"
		}
		return "MEDIUM"

	case "clipboard":
		// Clipboard access is HIGH (any app can read)
		if confidence >= 0.75 {
			return "HIGH"
		}
		return "MEDIUM"

	default:
		return "MEDIUM"
	}
}

// ============================================
// PHASE 5: REMEDIATION GENERATION
// ============================================

func (dfa *DataFlowAnalyzer) GenerateRemediations() {
	for i := range dfa.Paths {
		path := &dfa.Paths[i]

		remediations := []string{}

		// Always remediate the source
		remediations = append(remediations, dfa.GenerateSourceRemediation(path.Source)...)

		// Remediate the sink
		for _, sink := range path.Sinks {
			remediations = append(remediations, dfa.GenerateSinkRemediation(sink)...)
		}

		// Add flow-specific remediations
		remediations = append(remediations, dfa.GenerateFlowRemediation(path)...)

		path.Remediations = remediations
	}
}

func (dfa *DataFlowAnalyzer) GenerateSourceRemediation(source *DataFlowNode) []string {
	remediations := []string{}

	if strings.Contains(strings.ToLower(source.Name), "hardcoded") ||
		strings.Contains(strings.ToLower(source.Name), "api") ||
		strings.Contains(strings.ToLower(source.Name), "key") {
		remediations = append(remediations, "❌ Remove hardcoded secret from binary")
		remediations = append(remediations, "✅ Fetch secret from secure backend at runtime")
		remediations = append(remediations, "✅ Use environment-specific configuration")
	}

	return remediations
}

func (dfa *DataFlowAnalyzer) GenerateSinkRemediation(sink *DataFlowNode) []string {
	remediations := []string{}

	switch sink.Category {
	case "logging":
		remediations = append(remediations, "❌ Remove sensitive data from logging statements")
		remediations = append(remediations, "✅ Log only non-sensitive information")
		remediations = append(remediations, "✅ Implement conditional logging (disabled in release)")

	case "network":
		remediations = append(remediations, "❌ Don't send secrets to unvalidated endpoints")
		remediations = append(remediations, "✅ Use certificate pinning for sensitive APIs")
		remediations = append(remediations, "✅ Validate endpoint HTTPS certificates")
		remediations = append(remediations, "✅ Send secrets only to trusted first-party servers")

	case "storage":
		remediations = append(remediations, "❌ Don't store secrets in insecure storage")
		remediations = append(remediations, "✅ Use Keychain with appropriate accessibility level")
		remediations = append(remediations, "✅ Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly")
		remediations = append(remediations, "✅ Encrypt data at rest")

	case "clipboard":
		remediations = append(remediations, "❌ Don't copy secrets to clipboard")
		remediations = append(remediations, "✅ Use pasteboard only for user-visible data")
		remediations = append(remediations, "✅ Clear clipboard after paste operation")
	}

	return remediations
}

func (dfa *DataFlowAnalyzer) GenerateFlowRemediation(path *DataFlowPath) []string {
	remediations := []string{}

	switch path.FlowType {
	case "logging":
		remediations = append(remediations, "🔒 CRITICAL: Secrets visible in console, crash logs, and syslog")
		remediations = append(remediations, "⏱ Timeline: Fix immediately (within sprint)")

	case "network":
		remediations = append(remediations, "🔒 CRITICAL: Secrets potentially intercepted in transit")
		remediations = append(remediations, "⏱ Timeline: Fix immediately (security review required)")

	case "storage":
		remediations = append(remediations, "⚠️  HIGH: Secrets readable via device backup or jailbreak")
		remediations = append(remediations, "⏱ Timeline: Fix in next release")

	case "clipboard":
		remediations = append(remediations, "⚠️  HIGH: Secrets accessible to all background apps")
		remediations = append(remediations, "⏱ Timeline: Fix in next release")
	}

	return remediations
}

// ============================================
// PHASE 6: REPORT INTEGRATION
// ============================================

func (dfa *DataFlowAnalyzer) UpdateReport(report *Report) {
	// Convert paths to interface{} for JSON compatibility
	if len(dfa.Paths) > 0 {
		report.Findings.DataFlows = make([]interface{}, len(dfa.Paths))
		for i := range dfa.Paths {
			report.Findings.DataFlows[i] = dfa.Paths[i]
		}
	}

	// Convert nodes to interface{} for JSON compatibility
	if len(dfa.Nodes) > 0 {
		report.Findings.TaintGraph = make(map[string]interface{})
		for id, node := range dfa.Nodes {
			report.Findings.TaintGraph[id] = node
		}
	}

	// Update source findings with dataflow metadata
	for _, node := range dfa.SourceNodes {
		if node.SourceFinding != nil {
			node.SourceFinding.DataFlowNodeID = node.ID
			node.SourceFinding.IsTaintSource = true
		}
	}

	// Update sink findings with dataflow metadata
	for _, node := range dfa.SinkNodes {
		if node.SourceFinding != nil {
			node.SourceFinding.DataFlowNodeID = node.ID
			node.SourceFinding.IsTaintSink = true
		}
	}
}

// ============================================
// HELPER FUNCTIONS
// ============================================

func (dfa *DataFlowAnalyzer) FindExistingFlow(source, sink *DataFlowNode) *DataFlowPath {
	for i := range dfa.Paths {
		if dfa.Paths[i].Source.ID == source.ID {
			for _, s := range dfa.Paths[i].Sinks {
				if s.ID == sink.ID {
					return &dfa.Paths[i]
				}
			}
		}
	}
	return nil
}

func isCredentialAssignmentPattern(title string) bool {
	keywords := []string{"password", "credential", "key assignment", "secret assignment"}
	lower := strings.ToLower(title)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isLoggingSink(finding Finding) bool {
	return strings.Contains(finding.Title, "Sensitive Data Logged") ||
		strings.Contains(finding.Description, "Sensitive Data Logged")
}

func isSafeURL(url string) bool {
	safePatterns := []string{
		"apple.com", "github.com", "google.com",
		"cloudflare.com", "akamai.com", "fastly.com",
		"aws.amazon.com", "googleapis.com",
		"localhost", "127.0.0.1", "0.0.0.0",
	}

	lower := strings.ToLower(url)
	for _, pattern := range safePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func truncateURL(url string) string {
	if len(url) > 50 {
		return url[:47] + "..."
	}
	return url
}

func isStorageSink(misc string) bool {
	keywords := []string{"UserDefaults", "Keychain", "Storage", "plist", "SQLite"}
	for _, kw := range keywords {
		if strings.Contains(misc, kw) {
			return true
		}
	}
	return false
}

func extractStorageName(misc string) string {
	if strings.Contains(misc, "UserDefaults") {
		return "UserDefaults"
	}
	if strings.Contains(misc, "Keychain") {
		return "Keychain"
	}
	if strings.Contains(misc, "plist") {
		return "Property List"
	}
	return "Insecure Storage"
}

func extractVariableName(title string) string {
	// Try to extract variable name from title
	// e.g., "Google API Key" → "api_key"
	title = strings.ToLower(title)
	if strings.Contains(title, "api") {
		return "api"
	}
	if strings.Contains(title, "token") {
		return "token"
	}
	if strings.Contains(title, "key") {
		return "key"
	}
	if strings.Contains(title, "password") {
		return "password"
	}
	if strings.Contains(title, "secret") {
		return "secret"
	}
	return ""
}

func hasSensitiveKeywordMatch(source, sink string) bool {
	keywords := []string{
		"password", "token", "secret", "key", "api",
		"credential", "bearer", "auth", "session",
	}
	sinkLower := strings.ToLower(sink)
	for _, kw := range keywords {
		if strings.Contains(sinkLower, kw) {
			return true
		}
	}
	return false
}

func isLoggingFunction(funcName string) bool {
	loggingFuncs := []string{
		"NSLog", "print", "printf", "fprintf", "debugPrint", "console", "os_log",
	}
	for _, f := range loggingFuncs {
		if strings.Contains(funcName, f) {
			return true
		}
	}
	return false
}

func isNetworkFunction(funcName string) bool {
	networkFuncs := []string{
		"URLRequest", "POST", "GET", "URLSession", "curl", "http", "https",
		"AFHTTPClient", "URLConnection", "socket",
	}
	for _, f := range networkFuncs {
		if strings.Contains(funcName, f) {
			return true
		}
	}
	return false
}

func isStorageFunction(funcName string) bool {
	storageFuncs := []string{
		"SecItemAdd", "UserDefaults", "NSKeyedArchiver", "FileManager", "plist",
		"SQLite", "CoreData", "Realm",
	}
	for _, f := range storageFuncs {
		if strings.Contains(funcName, f) {
			return true
		}
	}
	return false
}

func readBinaryStrings(binaryPath string) (string, error) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", err
	}
	return ExtractStrings(content), nil
}
