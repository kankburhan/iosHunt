package core

import (
	"fmt"
	"os/exec"
	"strings"
)

// Device represents a connected Frida device
type Device struct {
	ID   string
	Type string
	Name string
}

// GetConnectedDevice returns the first USB device found via frida-ls-devices
func GetConnectedDevice() (*Device, error) {
	cmd := exec.Command("frida-ls-devices")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run frida-ls-devices: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Skip header or empty lines
		if strings.HasPrefix(line, "Id") || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Format: Id Type Name...
			id := fields[0]
			dtype := fields[1]
			name := strings.Join(fields[2:], " ")

			if dtype == "usb" {
				return &Device{
					ID:   id,
					Type: dtype,
					Name: name,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no USB device found")
}
