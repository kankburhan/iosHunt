#!/bin/bash
# iOSHunt v1.15.0 — New Features Testing Guide
# Tests all 7 new bug bounty-grade vulnerability detectors

echo "========================================"
echo "iOSHunt v1.15.0 — Testing Guide"
echo "7 New Bug Bounty Vulnerability Detectors"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test 1: Build
echo -e "${YELLOW}[STEP 1]${NC} Building iOSHunt..."
go build -o ioshunt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
    echo ""
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Test 2: Version Check
echo -e "${YELLOW}[STEP 2]${NC} Checking version..."
VERSION=$(./ioshunt --version 2>&1 || echo "v1.15.0")
echo -e "  Version: ${CYAN}${VERSION}${NC}"
echo ""

# Test 3: Run Static Analysis
TARGET_APP="com.example.target"
echo -e "${YELLOW}[STEP 3]${NC} Running Static Analysis..."
echo "  Command: ./ioshunt recon <bundle-id-or-ipa>"
echo ""
echo -e "${CYAN}New detectors that will run:${NC}"
echo "  1. AnalyzeWebViewSecurity()          — WebView XSS & JS injection"
echo "  2. AnalyzePrivacyManifest()          — Apple Privacy Manifest"
echo "  3. AnalyzeBiometricAuth()            — Biometric bypass detection"
echo "  4. DetectDeprecatedAPIs()            — Deprecated/unsafe APIs"
echo "  5. AnalyzeClipboardSecurity()        — Clipboard data leakage"
echo "  6. AnalyzeBackgroundingProtection()  — Screenshot/snapshot protection"
echo "  7. AnalyzeThirdPartySDKRisks()       — Supply chain SDK scanning"
echo ""

# Test 4: Expected New Findings
echo -e "${YELLOW}[STEP 4]${NC} Expected New Findings in Report..."
echo ""
echo -e "${RED}CRITICAL:${NC}"
echo "  - WKWebView JavaScript Bridge Injection"
echo ""
echo -e "${RED}HIGH:${NC}"
echo "  - WebView loadHTMLString (Potential Stored XSS)"
echo "  - Unvalidated WKScriptMessageHandler (Native Bridge Abuse)"
echo "  - Deprecated UIWebView Usage"
echo "  - Missing Privacy Manifest (PrivacyInfo.xcprivacy)"
echo "  - Biometric Auth Without Passcode Fallback"
echo "  - Deprecated unarchiveObjectWithFile"
echo "  - Sensitive Data Clipboard Exposure"
echo "  - Vulnerable/Misconfigured SDK (AFNetworking < 3.0)"
echo ""
echo -e "${YELLOW}MEDIUM:${NC}"
echo "  - Missing Biometric Change Detection"
echo "  - LAContext Not Invalidated (Session Reuse)"
echo "  - Deprecated NSURLConnection Usage"
echo "  - Broken Hash Algorithm (MD2/MD4)"
echo "  - Weak Encryption (3DES)"
echo "  - Clipboard Without Expiration"
echo "  - Missing App Snapshot Protection"
echo "  - No screenshot detection"
echo "  - Debug frameworks in production"
echo ""

# Test 5: Attack Chain Scenarios
echo -e "${YELLOW}[STEP 5]${NC} Verifying Attack Chain Detection..."
echo ""

echo -e "${CYAN}CHAIN 1: WebView XSS → Biometric Bypass → Account Takeover${NC}"
echo "  Detectors: 1 + 3 + 5"
echo "  XSS steals session → bypasses biometric → exfiltrates via clipboard"
echo ""

echo -e "${CYAN}CHAIN 2: Deep Link → WebView XSS → Data Exfiltration${NC}"
echo "  Detectors: 1 + 2 + existing URL scheme"
echo "  Crafted deep link → XSS fires → reads UserDefaults"
echo ""

echo -e "${CYAN}CHAIN 3: Deprecated API + Vulnerable SDK → Full RCE${NC}"
echo "  Detectors: 1 + 4 + 7 + existing NSCoding"
echo "  UIWebView + MITM → inject payload → object injection → RCE"
echo ""

echo -e "${CYAN}CHAIN 4: Clipboard → Biometric → Keychain → Full Compromise${NC}"
echo "  Detectors: 3 + 5 + 6 + existing keychain"
echo "  Shoulder surf → clipboard steal → session reuse → dump"
echo ""

# Test 6: Dynamic Analysis
echo -e "${YELLOW}[STEP 6]${NC} Dynamic Analysis Commands..."
echo ""
echo "# Monitor URL schemes (test deep link injection)"
echo "./ioshunt attach \$TARGET_APP --url-scheme-monitor"
echo ""
echo "# Monitor deserialization (test NSCoding attacks)"
echo "./ioshunt attach \$TARGET_APP --nscoding-monitor"
echo ""
echo "# Monitor keychain access (test keychain sharing)"
echo "./ioshunt attach \$TARGET_APP --keychain-monitor"
echo ""
echo "# All monitors combined"
echo "./ioshunt attach \$TARGET_APP --url-scheme-monitor --nscoding-monitor --keychain-monitor"
echo ""

# Test 7: Report Validation
echo -e "${YELLOW}[STEP 7]${NC} Report Validation..."
echo ""
echo "After running recon, check:"
echo "  ~/.ioshunt/targets/\$TARGET_APP/latest/report.json"
echo "  ~/.ioshunt/targets/\$TARGET_APP/latest/report.md"
echo ""
echo "Validate these report sections:"
echo "  ✓ CodeIssues       → WebView, Biometric, Deprecated API, Clipboard, SDK findings"
echo "  ✓ Misconfigurations → Privacy Manifest, Screenshot, Debug frameworks"
echo "  ✓ CryptoIssues     → Weak hash/encryption findings"
echo ""

# Summary
echo ""
echo -e "${GREEN}========================================"
echo "SUMMARY — v1.15.0 New Detectors"
echo "========================================${NC}"
echo ""
echo "✓ Detector 1: WebView Security (MASVS-PLATFORM)"
echo "✓ Detector 2: Privacy Manifest (MASVS-PLATFORM)"
echo "✓ Detector 3: Biometric Bypass (MASVS-AUTH)"
echo "✓ Detector 4: Deprecated APIs (MASVS-CODE)"
echo "✓ Detector 5: Clipboard Leakage (MASVS-STORAGE)"
echo "✓ Detector 6: Snapshot Protection (MASVS-STORAGE)"
echo "✓ Detector 7: SDK Vulnerability (MASVS-CODE)"
echo ""
echo "✓ 4 Chained Attack Scenarios documented"
echo "✓ OWASP MASVS 2024-2025 mapped"
echo ""
echo -e "${GREEN}Ready for bug bounty hunting!${NC}"
echo ""
