package core

import (
	"fmt"
	"os"
	"os/exec"
)

// InstallApp installs the app to the connected device
func InstallApp(appPath, deviceID string) error {
	fmt.Printf("[*] Installing %s to device...\n", appPath)

	args := []string{"--bundle", appPath}
	if deviceID != "" {
		args = append(args, "--id", deviceID)
	}

	// Just install for now. We might want to debug later.
	// ios-deploy flags:
	// -b, --bundle <bundle.app>
	// -i, --id <device_id>
	// -d, --debug (launch and debug)
	// -L, --justlaunch (launch only)
	// -m, --noinstall (do not install, just debug/launch)

	// For "install" command, we usually just want to install.
	// But the user flow says "Install -> Launch -> Attach".
	// So maybe we should just install here.

	cmd := exec.Command("ios-deploy", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ios-deploy failed: %v", err)
	}

	fmt.Println("[+] Installation successful.")
	return nil
}

// LaunchApp launches the app on the device
// This might require the bundle ID, not path, depending on the tool.
// ios-deploy uses bundle path to find and launch?
// Actually ios-deploy launches by bundle path mostly.
// idevice-app-runner uses bundleID.
func LaunchApp(appPath, deviceID string) error {
	fmt.Println("[*] Launching app...")
	// ios-deploy --justlaunch --debug --bundle <path>
	// --debug is needed to wait for debugger? No, --justlaunch shouldn't wait?
	// Actually --justlaunch might return immediately.
	// If we want to attach frida, we might want to launch suspended or just launch.
	// Frida -f <bundle> can spawn it too.

	// If we use Frida to spawn, we don't need explicit launch here unless we want to use ios-deploy's capabilities.
	// The PRD says: 4.5 Device Deployment: Install patched IPA, Launch app.
	// 4.6 Runtime Control: Auto attach: frida -U -n <app> OR -f <bundle>

	// Let's implement Launch using ios-deploy just in case.
	args := []string{"--justlaunch", "--bundle", appPath}
	if deviceID != "" {
		args = append(args, "--id", deviceID)
	}

	cmd := exec.Command("ios-deploy", args...)
	// launches and returns?
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launch failed: %v", err)
	}

	return nil
}
