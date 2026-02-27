#!/bin/bash
# iOSHunt New Features - Quick Testing Guide
# This script demonstrates how to test all 5 new security features

echo "========================================"
echo "iOSHunt New Features Testing Guide"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Build the tool
echo -e "${YELLOW}[STEP 1]${NC} Building iOSHunt..."
go build -o ioshunt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}\n"
else
    echo -e "${RED}✗ Build failed${NC}\n"
    exit 1
fi

# Test 2: Test with a sample app
TARGET_APP="com.example.vulnerable"

echo -e "${YELLOW}[STEP 2]${NC} Running Static Analysis (Recon)..."
echo "Command: ./ioshunt recon $TARGET_APP"
echo ""
echo "Expected Output:"
echo "  ✓ New findings:"
echo "    - 'Unsafe NSCoding (Possible Object Injection)'"
echo "    - 'Unvalidated URL Scheme Handler'"
echo "    - 'Keychain Shared via App Groups'"
echo "    - 'Potential Background Data Leak'"
echo "    - 'App Extension Shared Container'"
echo ""
echo -e "${YELLOW}Run this command:${NC}"
echo "./ioshunt recon $TARGET_APP"
echo ""
read -p "Press Enter after running recon..."

# Test 3: Test Frida Hooks
echo ""
echo -e "${YELLOW}[STEP 3]${NC} Testing Dynamic Analysis (Frida Hooks)..."
echo ""

echo "3a) URL Scheme Monitor:"
echo "    Command: ./ioshunt attach $TARGET_APP --url-scheme-monitor"
echo "    Expected: Intercepts URL scheme calls"
echo "    Trigger: Tap on deep links in the app"
echo ""

echo "3b) NSCoding Monitor:"
echo "    Command: ./ioshunt attach $TARGET_APP --nscoding-monitor"
echo "    Expected: Shows object deserialization calls"
echo "    Trigger: App loads/saves objects (plist, data)"
echo ""

echo "3c) Keychain Monitor:"
echo "    Command: ./ioshunt attach $TARGET_APP --keychain-monitor"
echo "    Expected: Shows keychain access groups"
echo "    Trigger: App authenticates or stores tokens"
echo ""

echo -e "${YELLOW}Example Commands:${NC}"
echo ""
echo "# Monitor URL schemes"
echo "./ioshunt attach $TARGET_APP --url-scheme-monitor"
echo ""
echo "# Monitor deserialization"
echo "./ioshunt attach $TARGET_APP --nscoding-monitor"
echo ""
echo "# Monitor keychain"
echo "./ioshunt attach $TARGET_APP --keychain-monitor"
echo ""
echo "# Combine multiple monitors"
echo "./ioshunt attach $TARGET_APP --url-scheme-monitor --nscoding-monitor --keychain-monitor"
echo ""

# Test 4: Check Report
echo ""
echo -e "${YELLOW}[STEP 4]${NC} Analyzing the Report..."
echo ""
echo "After running recon, check ~/.ioshunt/targets/$TARGET_APP/latest/report.json"
echo ""
echo -e "${YELLOW}Look for these new findings:${NC}"
echo ""
echo "1. CodeIssues → Unsafe NSCoding"
echo "2. Misconfigurations → Keychain Shared via App Groups"
echo "3. CodeIssues → Unvalidated URL Scheme Handler"
echo "4. CodeIssues → Potential Background Data Leak"
echo "5. Misconfigurations → App Extension Shared Container"
echo ""

# Test 5: Vulnerability Scenarios
echo ""
echo -e "${YELLOW}[STEP 5]${NC} Real-World Vulnerability Scenarios..."
echo ""

echo "SCENARIO 1 - Keychain Stealing:"
echo "  1. Run: ./ioshunt recon bankingapp"
echo "  2. Find: 'Keychain Shared via App Groups: group.*'"
echo "  3. Create attacker app with same group"
echo "  4. Exploit: Read all keychain items → steal tokens"
echo ""

echo "SCENARIO 2 - Deep Link Injection:"
echo "  1. Run: ./ioshunt recon socialapp"
echo "  2. Find: 'Unvalidated URL Scheme Handler: socialapp://'"
echo "  3. Monitor: ./ioshunt attach socialapp --url-scheme-monitor"
echo "  4. Test: socialapp://profile?id=hacked"
echo "  5. Result: No validation → priv escalation"
echo ""

echo "SCENARIO 3 - Object Injection:"
echo "  1. Run: ./ioshunt recon ecommerceapp"
echo "  2. Find: 'Unsafe NSCoding (Possible Object Injection)'"
echo "  3. Monitor: ./ioshunt attach ecommerceapp --nscoding-monitor"
echo "  4. Trigger: Load/save cart items"
echo "  5. Exploit: Craft malicious plist → RCE"
echo ""

echo "SCENARIO 4 - Background Data Leak:"
echo "  1. Run: ./ioshunt recon financeapp"
echo "  2. Find: 'Potential Background Data Leak'"
echo "  3. Close app but data syncs in background"
echo "  4. MITM on WiFi → intercept API calls"
echo "  5. Steal: Account info, transactions"
echo ""

echo "SCENARIO 5 - Widget Data Exposure:"
echo "  1. Run: ./ioshunt recon weatherapp"
echo "  2. Find: 'App Extension Shared Container'"
echo "  3. Create app with same group"
echo "  4. Access shared container → see widget data"
echo "  5. Steal: Location, user preferences"
echo ""

# Summary
echo ""
echo -e "${GREEN}========================================"
echo "SUMMARY - All New Features Added:"
echo "========================================${NC}"
echo ""
echo "✓ Feature 1: Insecure NSCoding Detection"
echo "  └─ Frida Hook: ./ioshunt attach APP --nscoding-monitor"
echo ""
echo "✓ Feature 2: Keychain Sharing Analysis"
echo "  └─ Frida Hook: ./ioshunt attach APP --keychain-monitor"
echo ""
echo "✓ Feature 3: URL Scheme Validation Check"
echo "  └─ Frida Hook: ./ioshunt attach APP --url-scheme-monitor"
echo ""
echo "✓ Feature 4: Background Activity Detection"
echo "  └─ Static analysis: ./ioshunt recon APP"
echo ""
echo "✓ Feature 5: App Extension Security"
echo "  └─ Static analysis: ./ioshunt recon APP"
echo ""
echo -e "${GREEN}Ready to find real vulnerabilities!${NC}"
echo ""
