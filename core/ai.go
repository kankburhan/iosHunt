package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// chatMessage represents a message in the OpenAI chat format
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest represents the OpenAI chat completions request
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// chatResponse represents a non-streaming response
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// streamChunk represents a streaming SSE chunk
type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

const systemPrompt = `You are an expert iOS application security researcher and penetration tester.
You are analyzing the static analysis report from iOSHunt, an automated iOS security scanner.

Your task is to:
1. **Identify REAL, actionable vulnerabilities** — separate true positives from noise
2. **Rate severity** using: CRITICAL, HIGH, MEDIUM, LOW, INFO
3. **Provide exploitation guidance** — how would a pentester exploit each finding?
4. **Suggest Proof of Concept (PoC)** steps where applicable
5. **Map to OWASP MASVS** categories (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE)
6. **Recommend next steps** for dynamic testing with Frida

Format your response as a professional penetration test report in Markdown with:
- Executive Summary (2-3 sentences)
- Risk Dashboard (count by severity)
- Detailed Findings (grouped by category, each with: Title, Severity, Description, Impact, PoC, Remediation)
- Recommended Dynamic Testing Steps

Focus on findings in the APPLICATION code, not third-party SDK noise.
Be concise but thorough. Skip findings that are clearly false positives.`

// AnalyzeWithAI sends the report to an AI model for deep vulnerability analysis
func AnalyzeWithAI(cfg *Config, report *Report) (string, error) {
	// Build a condensed report summary for the AI
	reportJSON, err := buildCondensedReport(report)
	if err != nil {
		return "", fmt.Errorf("failed to prepare report: %v", err)
	}

	userPrompt := fmt.Sprintf("Analyze this iOS application security scan report and provide a professional vulnerability assessment:\n\n```json\n%s\n```", reportJSON)

	req := chatRequest{
		Model: cfg.AIModel,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream: true,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	// Build HTTP request
	url := strings.TrimSuffix(cfg.AIBaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cfg.AIAPIKey)

	client := &http.Client{Timeout: 5 * time.Minute}

	fmt.Printf("[*] Sending report to %s (model: %s)...\n", cfg.AIBaseURL, cfg.AIModel)

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Stream response
	var fullResponse strings.Builder
	scanner := bufio.NewScanner(resp.Body)

	// Increase scanner buffer for large chunks
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: {...}"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk streamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		for _, choice := range chunk.Choices {
			if choice.Delta.Content != "" {
				fmt.Print(choice.Delta.Content)
				fullResponse.WriteString(choice.Delta.Content)
			}
		}
	}

	fmt.Println() // Final newline after streaming

	if fullResponse.Len() == 0 {
		// Try non-streaming parse (some providers don't support streaming)
		return tryNonStreamingParse(resp.Body)
	}

	return fullResponse.String(), nil
}

// tryNonStreamingParse attempts to parse the response as a regular (non-streamed) response
func tryNonStreamingParse(body io.Reader) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(data, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) > 0 {
		content := chatResp.Choices[0].Message.Content
		fmt.Println(content)
		return content, nil
	}

	return "", fmt.Errorf("empty response from AI")
}

// buildCondensedReport creates a condensed JSON report suitable for AI context windows
func buildCondensedReport(report *Report) (string, error) {
	// Build a condensed struct with only the important parts
	condensed := map[string]interface{}{
		"app_info":     report.AppInfo,
		"binary":       report.BinaryAnalysis,
		"entitlements": report.Entitlements,
	}

	findings := map[string]interface{}{}

	// Misconfigs: always include
	if len(report.Findings.Misconfigurations) > 0 {
		findings["misconfigurations"] = report.Findings.Misconfigurations
	}

	// Secrets: limit to 30 most interesting
	if len(report.Findings.Secrets) > 0 {
		limit := 30
		if len(report.Findings.Secrets) < limit {
			limit = len(report.Findings.Secrets)
		}
		findings["secrets"] = report.Findings.Secrets[:limit]
		findings["secrets_total"] = len(report.Findings.Secrets)
	}

	// URLs: limit to 30
	if len(report.Findings.URLs) > 0 {
		limit := 30
		if len(report.Findings.URLs) < limit {
			limit = len(report.Findings.URLs)
		}
		findings["urls"] = report.Findings.URLs[:limit]
		findings["urls_total"] = len(report.Findings.URLs)
	}

	// Code Issues: always include all
	if len(report.Findings.CodeIssues) > 0 {
		findings["code_issues"] = report.Findings.CodeIssues
	}

	// Crypto: always include
	if len(report.Findings.CryptoIssues) > 0 {
		findings["crypto_issues"] = report.Findings.CryptoIssues
	}

	// Hardening: limit to 20
	if len(report.Findings.HardeningIssues) > 0 {
		limit := 20
		if len(report.Findings.HardeningIssues) < limit {
			limit = len(report.Findings.HardeningIssues)
		}
		findings["hardening_issues"] = report.Findings.HardeningIssues[:limit]
	}

	// Insecure storage: limit to 10
	if len(report.Findings.InsecureStorage) > 0 {
		limit := 10
		if len(report.Findings.InsecureStorage) < limit {
			limit = len(report.Findings.InsecureStorage)
		}
		findings["insecure_storage"] = report.Findings.InsecureStorage[:limit]
	}

	// Permissions
	if len(report.Findings.Permissions) > 0 {
		findings["permissions"] = report.Findings.Permissions
	}

	// Deep Links
	if len(report.Findings.DeepLinks.Schemes) > 0 || len(report.Findings.DeepLinks.Universal) > 0 {
		findings["deep_links"] = report.Findings.DeepLinks
	}

	// Trackers
	if len(report.Findings.Trackers) > 0 {
		findings["trackers"] = report.Findings.Trackers
	}

	condensed["findings"] = findings

	data, err := json.MarshalIndent(condensed, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// SaveAnalysis saves the AI analysis to a markdown file
func SaveAnalysis(path, content string) error {
	header := "# iOSHunt AI Vulnerability Analysis\n\n"
	header += "_Generated by iOSHunt AI Analyzer_\n\n---\n\n"
	return os.WriteFile(path, []byte(header+content), 0644)
}
