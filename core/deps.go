package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DependencyManager handles checking and installing external tools
type DependencyManager struct {
	BinDir string
}

func NewDependencyManager() *DependencyManager {
	// Use a local bin directory within the project or user's home
	home, _ := os.UserHomeDir()
	binDir := filepath.Join(home, ".ioshunt", "bin")
	os.MkdirAll(binDir, 0755)

	// Add to PATH for the current process
	os.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return &DependencyManager{
		BinDir: binDir,
	}
}

// CheckAndInstall ensures all required tools are available
func (dm *DependencyManager) CheckAndInstall() error {
	fmt.Println("[*] Checking dependencies...")

	if err := dm.ensureIpatool(); err != nil {
		return fmt.Errorf("ipatool check failed: %v", err)
	}

	if err := dm.ensureFridaGadget(); err != nil {
		return fmt.Errorf("frida gadget check failed: %v", err)
	}

	if err := dm.ensureInsertDylib(); err != nil {
		return fmt.Errorf("insert_dylib check failed: %v", err)
	}

	// Check for ios-deploy (cannot auto-install easily without brew)
	if _, err := exec.LookPath("ios-deploy"); err != nil {
		fmt.Println("[!] ios-deploy not found. Please install it: brew install ios-deploy")
	}

	return nil
}

// WriteCounter counts bytes written for progress bar
type WriteCounter struct {
	Total   uint64
	Current uint64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Current += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc *WriteCounter) PrintProgress() {
	fmt.Printf("\r%s", strings.Repeat(" ", 35))
	fmt.Printf("\r[↓] Downloading... %d bytes ", wc.Current)
	if wc.Total > 0 {
		percent := float64(wc.Current) / float64(wc.Total) * 100
		fmt.Printf("(%.0f%%)", percent)
	}
}

// downloadFile downloads a file from a URL to a local path with progress
func (dm *DependencyManager) downloadFile(url, dest string) error {
	fmt.Printf("[*] Downloading %s...\n", filepath.Base(dest))

	// Create the file
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create progress reporter
	counter := &WriteCounter{Total: uint64(resp.ContentLength)}
	if _, err = io.Copy(out, io.TeeReader(resp.Body, counter)); err != nil {
		return err
	}

	fmt.Print("\n")
	return nil
}

func (dm *DependencyManager) ensureIpatool() error {
	if _, err := exec.LookPath("ipatool"); err == nil {
		return nil
	}

	// Try installing via brew if available
	if _, err := exec.LookPath("brew"); err == nil {
		fmt.Println("[-] ipatool not found. Installing via brew...")
		cmd := exec.Command("brew", "tap", "maestro-cli/tap")
		cmd.Run()
		cmd = exec.Command("brew", "install", "maestro-cli/tap/ipatool")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Fallback to direct download
	// Assuming macOS arm64/amd64 based on runtime
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	} else {
		arch = "arm64"
	}

	version := "v2.1.4" // Hardcoded recent version
	filename := fmt.Sprintf("ipatool-%s-darwin-%s.zip", version, arch)
	url := fmt.Sprintf("https://github.com/maestro-cli/ipatool/releases/download/%s/%s", version, filename)

	destZip := filepath.Join(dm.BinDir, filename)
	if err := dm.downloadFile(url, destZip); err != nil {
		return fmt.Errorf("failed to download ipatool: %v", err)
	}

	// Unzip
	cmd := exec.Command("unzip", "-o", destZip, "-d", dm.BinDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unzip ipatool: %v", err)
	}
	os.Remove(destZip) // Cleanup

	// Verify
	ipaBin := filepath.Join(dm.BinDir, "ipatool")
	if _, err := os.Stat(ipaBin); err != nil {
		// Sometimes it might extract to a subdirectory?
		// But usually it's correct.
	} else {
		os.Chmod(ipaBin, 0755)
	}

	return nil
}

func (dm *DependencyManager) ensureFridaGadget() error {
	gadgetPath := filepath.Join(dm.BinDir, "FridaGadget.dylib")
	if _, err := os.Stat(gadgetPath); err == nil {
		return nil
	}

	fmt.Println("[-] FridaGadget.dylib not found. Checking local frida version...")

	// Get local frida version
	cmd := exec.Command("frida", "--version")
	out, err := cmd.Output()
	version := "16.2.1" // Default fallback
	if err == nil {
		version = strings.TrimSpace(string(out))
	} else {
		fmt.Println("[!] Frida CLI not found. Using default version " + version)
	}

	// Construct URL
	// https://github.com/frida/frida/releases/download/16.1.4/frida-gadget-16.1.4-ios-universal.dylib.xz
	url := fmt.Sprintf("https://github.com/frida/frida/releases/download/%s/frida-gadget-%s-ios-universal.dylib.xz", version, version)
	destXz := filepath.Join(dm.BinDir, "FridaGadget.dylib.xz")

	if err := dm.downloadFile(url, destXz); err != nil {
		return fmt.Errorf("failed to download frida gadget: %v", err)
	}

	// Decompress
	// Try xz command
	if _, err := exec.LookPath("xz"); err == nil {
		cmd := exec.Command("xz", "-d", destXz)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to extract frida gadget: %v", err)
		}
	} else {
		return fmt.Errorf("xz command not found, cannot decompress FridaGadget.dylib.xz")
	}

	return nil
}

func (dm *DependencyManager) ensureInsertDylib() error {
	if _, err := exec.LookPath("insert_dylib"); err == nil {
		return nil
	}

	// Check local bin
	localPath := filepath.Join(dm.BinDir, "insert_dylib")
	if _, err := os.Stat(localPath); err == nil {
		return nil
	}

	// insert_dylib doesn't have official binaries easily available on releases sometimes.
	// But let's check parsing logic if we want to support it.
	// For now, ask user to install is safer unless we build from source.
	fmt.Println("[!] insert_dylib not found. Please install: git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib && xcodebuild && cp build/Release/insert_dylib /usr/local/bin/")
	return nil
}
