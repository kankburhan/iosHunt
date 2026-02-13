package core

import (
	"os/exec"
	"strings"
)

// BinarySecurity holds binary security check results
type BinarySecurity struct {
	PIE         bool
	ARC         bool
	StackCanary bool
	Encrypted   bool
}

func CheckBinarySecurity(binaryPath string) (*BinarySecurity, error) {
	sec := &BinarySecurity{}

	// 1. Check PIE
	if out, err := exec.Command("otool", "-hv", binaryPath).CombinedOutput(); err == nil {
		if strings.Contains(string(out), "PIE") {
			sec.PIE = true
		}
	}

	// 2. Check Stack Canary & ARC (symbols)
	// Using nm or otool -Iv
	// nm is better for symbols
	if out, err := exec.Command("nm", "-u", binaryPath).CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "___stack_chk_fail") || strings.Contains(s, "___stack_chk_guard") {
			sec.StackCanary = true
		}
		if strings.Contains(s, "_objc_release") {
			sec.ARC = true
		}
	}

	// 3. Check Encryption (cryptid)
	// otool -l | grep cryptid
	if out, err := exec.Command("otool", "-l", binaryPath).CombinedOutput(); err == nil {
		if strings.Contains(string(out), "cryptid 1") {
			sec.Encrypted = true
		}
	}

	return sec, nil
}
