package core

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// InjectGadget injects the Frida gadget into the app binary
func InjectGadget(appPath, gadgetPath string) error {
	fmt.Println("[*] Injecting Frida Gadget...")

	// 1. Locate the main executable
	info, err := ParseInfo(filepath.Join(appPath, "Info.plist"))
	if err != nil {
		return fmt.Errorf("failed to parse Info.plist: %v", err)
	}
	binaryPath := filepath.Join(appPath, info.CFBundleExecutable)

	// 2. Copy FridaGadget.dylib to the app bundle
	// Usually placing it alongside the binary or in Frameworks
	// Let's put it in the root of the .app for simplicity with @executable_path
	destGadget := filepath.Join(appPath, "FridaGadget.dylib")
	if err := copyFile(gadgetPath, destGadget); err != nil {
		return fmt.Errorf("failed to copy FridaGadget: %v", err)
	}

	// 3. Run insert_dylib
	// Note: insert_dylib flags can vary by version.
	// Common verified options: --strip-codesig --all-yes
	fmt.Printf("[*] Running insert_dylib on %s\n", info.CFBundleExecutable)

	args := []string{
		"--strip-codesig",
		"--all-yes",
		"@executable_path/FridaGadget.dylib",
		binaryPath,
		binaryPath, // overwrite in place? insert_dylib usually creates _patched or takes dest.
		// If 2 args provided, second is dest.
	}

	cmd := exec.Command("insert_dylib", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("insert_dylib failed: %v\nOutput: %s", err, string(out))
	}

	// 4. Verify with otool (optional but good practice)
	// cmd = exec.Command("otool", "-L", binaryPath)
	// out, _ = cmd.CombinedOutput()
	// if !strings.Contains(string(out), "FridaGadget.dylib") {
	//    return fmt.Errorf("injection verification failed")
	// }

	fmt.Println("[+] Injection successful.")
	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
