package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	CurrentVersion = "v1.14.0"
	RepoOwner      = "kankburhan"
	RepoName       = "iosHunt"
	GitHubAPI      = "https://api.github.com/repos/" + RepoOwner + "/" + RepoName + "/releases/latest"
	GoInstallPath  = "github.com/kankburhan/iosHunt"
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

// CheckUpdate checks for a new version on GitHub and prints a notice if one is available.
func CheckUpdate() {
	client := http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get(GitHubAPI)
	if err != nil {
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

	if compareVersions(release.TagName, CurrentVersion) > 0 {
		fmt.Printf("\n%s %s is available! (Current: %s)\n",
			yellow("[!] Update:"), green(release.TagName), cyan(CurrentVersion))
		fmt.Printf("    Run %s to upgrade.\n\n", cyan("ioshunt update"))
	}
}

// compareVersions returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal.
// Performs proper semver numeric comparison (major.minor.patch).
func compareVersions(v1, v2 string) int {
	parse := func(v string) [3]int {
		v = strings.TrimPrefix(v, "v")
		parts := strings.SplitN(v, ".", 3)
		var nums [3]int
		for i, p := range parts {
			if i >= 3 {
				break
			}
			// strip pre-release suffix (e.g. "-beta.1")
			p = strings.SplitN(p, "-", 2)[0]
			nums[i], _ = strconv.Atoi(p)
		}
		return nums
	}

	a := parse(v1)
	b := parse(v2)
	for i := 0; i < 3; i++ {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}
