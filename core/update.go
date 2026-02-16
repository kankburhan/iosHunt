package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	CurrentVersion = "v1.11.0"
	RepoOwner      = "kankburhan"
	RepoName       = "iosHunt"
	GitHubAPI      = "https://api.github.com/repos/" + RepoOwner + "/" + RepoName + "/releases/latest"
)

type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
}

var (
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
)

// CheckUpdate checks for a new version on GitHub
func CheckUpdate() {
	// dedicated goroutine to not block startup significantly,
	// but we might want to show it before the prompt if it's fast.
	// For CLI tools, usually we put it in a channel or just run it with a short timeout.

	client := http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(GitHubAPI)
	if err != nil {
		// Silent fail on network error
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}

	// Simple tag comparison
	// Assuming tags are like "v1.0.0", "v1.0.1"
	if compareVersions(release.TagName, CurrentVersion) > 0 {
		fmt.Printf("\n%s %s is available! (Current: %s)\n", yellow("[!] Update:"), green(release.TagName), cyan(CurrentVersion))
		fmt.Printf("Run %s to upgrade.\n\n", cyan("ioshunt update"))
	}
}

// compareVersions returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	if v1 == v2 {
		return 0
	}

	// Very basic semver compare for now
	return strings.Compare(v1, v2)
}
