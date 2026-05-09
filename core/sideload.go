package core

// Non-jailbreak deployment automation.
//
// Provides a layered installer that prefers libimobiledevice (ideviceinstaller)
// for non-JB devices, then falls back to ios-deploy and AltStore.
//
// Workflow:
//   1. Discover device(s) via idevice_id
//   2. Validate pairing via idevicepair
//   3. Install resigned IPA via ideviceinstaller
//   4. Launch via idevicedebug (if available) or instruct user
//   5. Verify install via ideviceinstaller -l

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// SideloadDevice describes a non-JB iOS device discovered via libimobiledevice
type SideloadDevice struct {
	UDID        string `json:"udid"`
	Name        string `json:"name"`
	ProductType string `json:"product_type"`
	IOSVersion  string `json:"ios_version"`
	Paired      bool   `json:"paired"`
	Available   bool   `json:"available"` // pingable via ideviceinfo
}

// SideloadOptions configures a single deployment
type SideloadOptions struct {
	IPAPath    string
	BundleID   string // for verification post-install
	DeviceUDID string // empty = first device
	Method     string // "auto" | "idevice" | "ios-deploy" | "altstore"
	Launch     bool   // try to launch after install
}

// SideloadResult describes outcome
type SideloadResult struct {
	Success      bool   `json:"success"`
	DeviceUDID   string `json:"device_udid"`
	Method       string `json:"method"`
	BundleID     string `json:"bundle_id,omitempty"`
	InstalledVer string `json:"installed_version,omitempty"`
	Detail       string `json:"detail"`
	Stdout       string `json:"stdout,omitempty"`
	Stderr       string `json:"stderr,omitempty"`
}

// ListSideloadDevices returns all devices visible to libimobiledevice
func ListSideloadDevices() ([]SideloadDevice, error) {
	if _, err := exec.LookPath("idevice_id"); err != nil {
		return nil, fmt.Errorf("idevice_id not installed (brew install libimobiledevice)")
	}
	out, err := exec.Command("idevice_id", "-l").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("idevice_id failed: %v: %s", err, out)
	}
	udids := strings.Fields(strings.TrimSpace(string(out)))
	devices := make([]SideloadDevice, 0, len(udids))
	for _, u := range udids {
		d := SideloadDevice{UDID: u}
		// Pull metadata
		if name, err := exec.Command("ideviceinfo", "-u", u, "-k", "DeviceName").Output(); err == nil {
			d.Name = strings.TrimSpace(string(name))
		}
		if pt, err := exec.Command("ideviceinfo", "-u", u, "-k", "ProductType").Output(); err == nil {
			d.ProductType = strings.TrimSpace(string(pt))
		}
		if ver, err := exec.Command("ideviceinfo", "-u", u, "-k", "ProductVersion").Output(); err == nil {
			d.IOSVersion = strings.TrimSpace(string(ver))
		}
		// Pairing check
		if pairOut, err := exec.Command("idevicepair", "-u", u, "validate").CombinedOutput(); err == nil {
			d.Paired = strings.Contains(string(pairOut), "Validate")
		} else {
			d.Paired = false
		}
		d.Available = d.Name != ""
		devices = append(devices, d)
	}
	return devices, nil
}

// PairDevice runs idevicepair pair (requires user to tap "Trust" on device)
func PairDevice(udid string) error {
	if _, err := exec.LookPath("idevicepair"); err != nil {
		return fmt.Errorf("idevicepair not installed")
	}
	args := []string{"pair"}
	if udid != "" {
		args = append([]string{"-u", udid}, args...)
	}
	out, err := exec.Command("idevicepair", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pair failed (tap Trust on device?): %v: %s", err, out)
	}
	if !strings.Contains(string(out), "SUCCESS") {
		return fmt.Errorf("pair did not succeed: %s", out)
	}
	return nil
}

// Sideload performs the full install flow with method fallback
func Sideload(opts SideloadOptions) SideloadResult {
	res := SideloadResult{
		DeviceUDID: opts.DeviceUDID,
		BundleID:   opts.BundleID,
	}

	if opts.IPAPath == "" {
		res.Detail = "IPAPath required"
		return res
	}

	// Auto-resolve device if empty
	if opts.DeviceUDID == "" {
		devs, err := ListSideloadDevices()
		if err != nil || len(devs) == 0 {
			res.Detail = "no devices available: " + fmt.Sprint(err)
			return res
		}
		opts.DeviceUDID = devs[0].UDID
		res.DeviceUDID = opts.DeviceUDID
	}

	method := opts.Method
	if method == "" || method == "auto" {
		method = pickBestMethod()
	}
	res.Method = method

	switch method {
	case "idevice":
		return sideloadIDevice(opts, res)
	case "ios-deploy":
		return sideloadIOSDeploy(opts, res)
	case "altstore":
		return sideloadAltStore(opts, res)
	default:
		res.Detail = "unknown method: " + method
		return res
	}
}

// pickBestMethod chooses installer in priority order
func pickBestMethod() string {
	if _, err := exec.LookPath("ideviceinstaller"); err == nil {
		return "idevice"
	}
	if _, err := exec.LookPath("ios-deploy"); err == nil {
		return "ios-deploy"
	}
	if _, err := exec.LookPath("altserver"); err == nil {
		return "altstore"
	}
	return "idevice" // attempt idevice for clearer error
}

func sideloadIDevice(opts SideloadOptions, res SideloadResult) SideloadResult {
	if _, err := exec.LookPath("ideviceinstaller"); err != nil {
		res.Detail = "ideviceinstaller not installed (brew install ideviceinstaller)"
		return res
	}
	args := []string{"-u", opts.DeviceUDID, "-i", opts.IPAPath}
	out, err := exec.Command("ideviceinstaller", args...).CombinedOutput()
	res.Stdout = string(out)
	if err != nil {
		res.Detail = fmt.Sprintf("install failed: %v", err)
		return res
	}
	if !strings.Contains(string(out), "Install") && !strings.Contains(string(out), "Complete") {
		res.Detail = "install output unexpected: " + truncateSL(string(out), 300)
		return res
	}
	res.Success = true
	res.Detail = "installed via ideviceinstaller"

	// Verify by listing apps
	if opts.BundleID != "" {
		listOut, _ := exec.Command("ideviceinstaller", "-u", opts.DeviceUDID, "-l", "-o", "list_user", "-o", "xml").CombinedOutput()
		if strings.Contains(string(listOut), opts.BundleID) {
			res.Detail += " (verified in installed list)"
		}
	}

	if opts.Launch {
		_ = launchApp(opts.DeviceUDID, opts.BundleID, &res)
	}
	return res
}

func sideloadIOSDeploy(opts SideloadOptions, res SideloadResult) SideloadResult {
	if _, err := exec.LookPath("ios-deploy"); err != nil {
		res.Detail = "ios-deploy not installed (npm i -g ios-deploy)"
		return res
	}
	args := []string{"--bundle", opts.IPAPath}
	if opts.DeviceUDID != "" {
		args = append(args, "--id", opts.DeviceUDID)
	}
	if opts.Launch {
		args = append(args, "--justlaunch")
	}
	out, err := exec.Command("ios-deploy", args...).CombinedOutput()
	res.Stdout = string(out)
	if err != nil {
		res.Detail = fmt.Sprintf("ios-deploy failed: %v", err)
		return res
	}
	res.Success = true
	res.Detail = "installed via ios-deploy"
	return res
}

func sideloadAltStore(opts SideloadOptions, res SideloadResult) SideloadResult {
	if _, err := exec.LookPath("altserver"); err != nil {
		res.Detail = "altserver not installed (download from altstore.io)"
		return res
	}
	args := []string{"--install-app", "--app-path", opts.IPAPath}
	if opts.DeviceUDID != "" {
		args = append(args, "--udid", opts.DeviceUDID)
	}
	out, err := exec.Command("altserver", args...).CombinedOutput()
	res.Stdout = string(out)
	if err != nil {
		res.Detail = fmt.Sprintf("altserver failed: %v", err)
		return res
	}
	res.Success = true
	res.Detail = "installed via AltStore (altserver)"
	return res
}

// launchApp tries idevicedebug run if available
func launchApp(udid, bundleID string, res *SideloadResult) error {
	if bundleID == "" {
		return fmt.Errorf("bundle ID required")
	}
	if _, err := exec.LookPath("idevicedebug"); err != nil {
		res.Detail += " (launch skipped — idevicedebug not installed)"
		return err
	}
	cmd := exec.Command("idevicedebug", "-u", udid, "run", bundleID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Detail += fmt.Sprintf(" (launch failed: %v)", err)
		return err
	}
	res.Detail += " — launched via idevicedebug"
	res.Stdout += "\n" + string(out)
	return nil
}

// UninstallApp removes an app by bundle ID via ideviceinstaller
func UninstallApp(udid, bundleID string) error {
	if _, err := exec.LookPath("ideviceinstaller"); err != nil {
		return fmt.Errorf("ideviceinstaller not installed")
	}
	args := []string{"-U", bundleID}
	if udid != "" {
		args = append([]string{"-u", udid}, args...)
	}
	out, err := exec.Command("ideviceinstaller", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("uninstall failed: %v: %s", err, out)
	}
	return nil
}

// ListInstalledApps returns installed user apps as a simple slice of bundle IDs
func ListInstalledApps(udid string) ([]string, error) {
	if _, err := exec.LookPath("ideviceinstaller"); err != nil {
		return nil, fmt.Errorf("ideviceinstaller not installed")
	}
	args := []string{"-l", "-o", "list_user"}
	if udid != "" {
		args = append([]string{"-u", udid}, args...)
	}
	out, err := exec.Command("ideviceinstaller", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list failed: %v: %s", err, out)
	}
	bundles := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Format: "com.example.app - AppName 1.0.0"
		if idx := strings.Index(line, " - "); idx > 0 {
			bundles = append(bundles, line[:idx])
		}
	}
	return bundles, nil
}

// SideloadAndDeployJSON returns a JSON-friendly wrapper of full pipeline output
func SideloadAndDeployJSON(opts SideloadOptions) (string, SideloadResult) {
	res := Sideload(opts)
	js, _ := json.MarshalIndent(res, "", "  ")
	return string(js), res
}

func truncateSL(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
