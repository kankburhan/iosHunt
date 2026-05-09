package core

// Evidence collection for confirmed findings.
// Captures runtime artifacts that prove a vulnerability is exploitable:
//   - Screenshots via idevicescreenshot (libimobiledevice — non-JB friendly)
//   - Network capture via rvictl + tcpdump (non-JB, requires user-installed Xcode)
//   - Frida hook output as text dumps
//   - Session bundles (tar) for hand-off
//
// All captures are saved under <OutputDir>/<SessionID>/<finding-id>/...

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// EvidenceCollector manages on-disk evidence per pentest session
type EvidenceCollector struct {
	OutputDir string
	SessionID string
}

// NewEvidenceCollector creates an isolated evidence directory for this session
func NewEvidenceCollector(baseDir string) *EvidenceCollector {
	if baseDir == "" {
		baseDir = "./reports/evidence"
	}
	sessionID := time.Now().UTC().Format("20060102_150405")
	dir := filepath.Join(baseDir, sessionID)
	_ = os.MkdirAll(dir, 0755)
	return &EvidenceCollector{
		OutputDir: dir,
		SessionID: sessionID,
	}
}

// dirFor returns and ensures a per-finding subdir
func (ec *EvidenceCollector) dirFor(findingID string) string {
	if findingID == "" {
		findingID = "general"
	}
	d := filepath.Join(ec.OutputDir, findingID)
	_ = os.MkdirAll(d, 0755)
	return d
}

// CaptureScreenshot uses idevicescreenshot to grab a PNG from a non-JB device.
// Returns path to the saved PNG. Empty deviceID uses default device.
func (ec *EvidenceCollector) CaptureScreenshot(findingID, deviceID string) (string, error) {
	if _, err := exec.LookPath("idevicescreenshot"); err != nil {
		return "", fmt.Errorf("idevicescreenshot not installed (brew install libimobiledevice)")
	}
	dst := filepath.Join(ec.dirFor(findingID), fmt.Sprintf("screenshot_%d.png", time.Now().Unix()))
	args := []string{dst}
	if deviceID != "" {
		args = append([]string{"-u", deviceID}, args...)
	}
	cmd := exec.Command("idevicescreenshot", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("idevicescreenshot failed: %v: %s", err, out)
	}
	if _, err := os.Stat(dst); err != nil {
		return "", fmt.Errorf("screenshot not produced at %s", dst)
	}
	return dst, nil
}

// SaveFridaOutput writes captured Frida script stdout as evidence
func (ec *EvidenceCollector) SaveFridaOutput(findingID, scriptName, output string) (string, error) {
	d := ec.dirFor(findingID)
	name := fmt.Sprintf("frida_%s_%d.log", safeFilename(scriptName), time.Now().Unix())
	path := filepath.Join(d, name)
	header := fmt.Sprintf("# Frida hook output — %s\n# captured: %s\n# script: %s\n\n",
		findingID, time.Now().UTC().Format(time.RFC3339), scriptName)
	if err := os.WriteFile(path, []byte(header+output), 0644); err != nil {
		return "", err
	}
	return path, nil
}

// SaveRawArtifact dumps an arbitrary blob (e.g. keychain JSON, NSUserDefaults plist)
func (ec *EvidenceCollector) SaveRawArtifact(findingID, name string, data []byte) (string, error) {
	d := ec.dirFor(findingID)
	path := filepath.Join(d, fmt.Sprintf("%s_%d.bin", safeFilename(name), time.Now().Unix()))
	return path, os.WriteFile(path, data, 0644)
}

// NetCaptureHandle tracks a running rvictl + tcpdump session
type NetCaptureHandle struct {
	DeviceUDID string
	PcapPath   string
	cmd        *exec.Cmd
	rviSetup   bool
}

// StartNetworkCapture starts an rvictl-backed pcap on a non-JB device.
// Requires Xcode (rvictl is /Library/Apple/usr/bin/rvictl). User must run sudo once.
func (ec *EvidenceCollector) StartNetworkCapture(findingID, deviceUDID string) (*NetCaptureHandle, error) {
	if deviceUDID == "" {
		return nil, fmt.Errorf("deviceUDID required for rvictl")
	}
	if _, err := exec.LookPath("rvictl"); err != nil {
		// Try canonical path
		if _, err2 := os.Stat("/Library/Apple/usr/bin/rvictl"); err2 != nil {
			return nil, fmt.Errorf("rvictl not found — install Xcode + 'xcode-select --install'")
		}
	}

	pcap := filepath.Join(ec.dirFor(findingID), fmt.Sprintf("netcap_%d.pcap", time.Now().Unix()))

	// Bring up RVI interface (idempotent)
	if out, err := exec.Command("rvictl", "-s", deviceUDID).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("rvictl -s failed: %v: %s", err, out)
	}

	// Find the rvi interface (usually rvi0)
	iface := "rvi0"
	cmd := exec.Command("sudo", "tcpdump", "-i", iface, "-w", pcap, "-U")
	if err := cmd.Start(); err != nil {
		_ = exec.Command("rvictl", "-x", deviceUDID).Run()
		return nil, fmt.Errorf("tcpdump start failed: %v", err)
	}

	return &NetCaptureHandle{
		DeviceUDID: deviceUDID,
		PcapPath:   pcap,
		cmd:        cmd,
		rviSetup:   true,
	}, nil
}

// Stop tears down the tcpdump + rvi interface
func (h *NetCaptureHandle) Stop() error {
	if h == nil {
		return nil
	}
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
	if h.rviSetup {
		_ = exec.Command("rvictl", "-x", h.DeviceUDID).Run()
	}
	return nil
}

// CaptureFile pulls a file from app sandbox (jailbroken only, via Frida).
// For non-JB, this is a no-op stub — callers should use Frida hooks instead.
func (ec *EvidenceCollector) CaptureFile(findingID, devicePath string) (string, error) {
	return "", fmt.Errorf("file pull from sandbox requires JB or Frida hook (use SaveFridaOutput)")
}

// SaveCurlReplay records a manual curl reproduction
func (ec *EvidenceCollector) SaveCurlReplay(findingID string, request, response string) (string, error) {
	d := ec.dirFor(findingID)
	path := filepath.Join(d, fmt.Sprintf("curl_replay_%d.txt", time.Now().Unix()))
	body := fmt.Sprintf("# Curl replay — %s\n# captured: %s\n\n=== REQUEST ===\n%s\n\n=== RESPONSE ===\n%s\n",
		findingID, time.Now().UTC().Format(time.RFC3339), request, response)
	return path, os.WriteFile(path, []byte(body), 0644)
}

// BundleSession packages all evidence for this session into a tar.gz
func (ec *EvidenceCollector) BundleSession() (string, error) {
	bundle := filepath.Join(filepath.Dir(ec.OutputDir), fmt.Sprintf("evidence_%s.tar.gz", ec.SessionID))
	f, err := os.Create(bundle)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	err = filepath.Walk(ec.OutputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Dir(ec.OutputDir), path)
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		fh, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fh.Close()
		_, err = io.Copy(tw, fh)
		return err
	})
	if err != nil {
		return "", err
	}
	return bundle, nil
}

// AttachToFinding records evidence on a Finding's Evidence slice
func (ec *EvidenceCollector) AttachToFinding(f *Finding, evType, path, description string) {
	if f == nil || path == "" {
		return
	}
	st, _ := os.Stat(path)
	var size int64
	if st != nil {
		size = st.Size()
	}
	f.Evidence = append(f.Evidence, Evidence{
		Type:        evType,
		Path:        path,
		Description: description,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
		Size:        size,
	})
}

// summarizeEvidence is a debug helper
func (ec *EvidenceCollector) summarizeEvidence() string {
	files, _ := filepath.Glob(filepath.Join(ec.OutputDir, "*", "*"))
	var b strings.Builder
	fmt.Fprintf(&b, "Evidence session: %s (%d artifacts)\n", ec.SessionID, len(files))
	for _, f := range files {
		fmt.Fprintf(&b, "  - %s\n", f)
	}
	return b.String()
}
