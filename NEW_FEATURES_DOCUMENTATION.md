# iOSHunt New Features Documentation (v1.15.0)

## Overview
Added **7 new bug bounty-grade vulnerability detectors** based on real-world research from **HackerOne, Bugcrowd, YesWeHack, and Intigriti**. All detectors mapped to **OWASP MASVS 2024-2025** categories.

---

## 📋 New Features (v1.15.0)

### **DETECTOR 1: WebView Security Analysis** (MASVS-PLATFORM)
**Function**: `AnalyzeWebViewSecurity()` | **Severity**: Critical-High

#### What It Detects:
- ✅ `WKWebView` + `evaluateJavaScript` without input sanitization (JS bridge injection)
- ✅ `loadHTMLString` with dynamic content (stored XSS)
- ✅ Unvalidated `WKScriptMessageHandler` (native bridge abuse)
- ✅ Deprecated `UIWebView` usage (no process isolation, Apple rejection)

#### Why It Matters:
WebView XSS is the #1 mobile web vulnerability reported on bug bounty platforms. A single XSS can escalate to full account takeover via native bridge access.

#### Attack Chain:
```
XSS in WebView → Access native JS bridge → Read keychain via bridge
→ Steal auth token → Account takeover
```

#### Bug Bounty Relevance:
| Platform | Typical Payout | Severity |
|----------|---------------|----------|
| HackerOne | $500-$5,000 | Medium-Critical |
| Bugcrowd | P2-P1 | High-Critical |
| YesWeHack | €300-€3,000 | Medium-Critical |

---

### **DETECTOR 2: Privacy Manifest Compliance** (MASVS-PLATFORM)
**Function**: `AnalyzePrivacyManifest()` | **Severity**: Medium-High

#### What It Detects:
- ✅ Missing `PrivacyInfo.xcprivacy` file
- ✅ Usage of Required Reason APIs without declaration:
  - `NSUserDefaults` / `UserDefaults.standard`
  - `mach_absolute_time` / `systemUptime`
  - `creationDate` / `modificationDate`
  - `fstat` / `activeInputModes`

#### Why It Matters:
Since **May 2024**, Apple requires all apps using Required Reason APIs to include a privacy manifest. Missing manifests result in App Store rejection and indicate potential device fingerprinting.

---

### **DETECTOR 3: Biometric Authentication Bypass** (MASVS-AUTH)
**Function**: `AnalyzeBiometricAuth()` | **Severity**: Medium-High

#### What It Detects:
- ✅ `deviceOwnerAuthenticationWithBiometrics` without passcode fallback
- ✅ Missing `evaluatedPolicyDomainState` check (enrollment change detection)
- ✅ `LAContext` without `invalidate()` call (session reuse)

#### Attack Scenarios:
1. **Enrollment Attack**: Attacker adds their fingerprint → app doesn't detect → bypass
2. **Replay Attack**: Frida hooks `evaluatePolicy` to always return success
3. **Session Reuse**: LAContext stays authenticated → no re-prompt required

#### Bug Bounty Relevance:
| Platform | Typical Payout | Severity |
|----------|---------------|----------|
| HackerOne | $500-$3,000 | Medium-High |
| Intigriti | €200-€2,000 | Medium-High |

---

### **DETECTOR 4: Deprecated/Unsafe API Detection** (MASVS-CODE)
**Function**: `DetectDeprecatedAPIs()` | **Severity**: Medium-High

#### What It Detects:
- ✅ `NSURLConnection` (deprecated since iOS 9, no HTTP/2, no cert transparency)
- ✅ `unarchiveObjectWithFile` (unsafe deserialization variant)
- ✅ `CC_MD2` / `CC_MD4` (completely broken hash algorithms)
- ✅ `kCCAlgorithm3DES` (Sweet32 attack vulnerable)
- ✅ `kCCKeySizeAES128` (consider AES-256 for sensitive data)

---

### **DETECTOR 5: Clipboard/Pasteboard Data Leakage** (MASVS-STORAGE)
**Function**: `AnalyzeClipboardSecurity()` | **Severity**: Medium-High

#### What It Detects:
- ✅ `UIPasteboard.general` with sensitive data context (password/token/credential)
- ✅ Missing `expirationDate` on clipboard items
- ✅ Cross-app clipboard access risk

#### Attack Scenario:
```
1. User copies password from password manager
2. Password goes to UIPasteboard.general (system clipboard)
3. Malicious app reads clipboard in background
4. Password stolen — no user interaction needed
5. Password stays in clipboard for hours (no expiration)
```

#### Bug Bounty Relevance:
| Platform | Typical Payout | Severity |
|----------|---------------|----------|
| Bugcrowd | P3-P2 | Medium-High |
| YesWeHack | €100-€1,000 | Medium |

---

### **DETECTOR 6: Screenshot/Background Caching Protection** (MASVS-STORAGE)
**Function**: `AnalyzeBackgroundingProtection()` | **Severity**: Medium

#### What It Detects:
- ✅ Missing `applicationWillResignActive` snapshot blur/overlay
- ✅ Absence of `userDidTakeScreenshotNotification` monitoring
- ✅ Only flags apps handling sensitive data (auth/financial context)

#### Attack Scenario:
```
Banking app open with balance → User presses Home
→ iOS captures screenshot → Visible in app switcher
→ Anyone nearby sees account balance, transactions
```

---

### **DETECTOR 7: Supply Chain / SDK Vulnerability Scanning** (MASVS-CODE)
**Function**: `AnalyzeThirdPartySDKRisks()` | **Severity**: Medium-High

#### What It Detects:
- ✅ AFNetworking 2.x (`AFHTTPRequestOperationManager`) — CVE-2015-3996
- ✅ Firebase debug mode (`FIRDebugEnabled`) in production
- ✅ Crashlytics PII logging (`CLSLog`)
- ✅ React Native debug bridge (`RCTBridge`) — port 8081 exposure
- ✅ Cordova/Capacitor file protocol access (`CDVCommandDelegateImpl`)
- ✅ Flutter debug mode (`flutter_tools`)
- ✅ Debug/test/mock frameworks in production build
- ✅ Excessive framework count (audit recommendation)

---

## ⛓️ Attack Chain Detection

The 7 new detectors can be **combined for maximum impact**:

### Chain 1: WebView XSS → Biometric Bypass → Account Takeover
```
Detectors: 1 + 3 + 5
XSS steals session → bypasses biometric → exfiltrates via clipboard
```

### Chain 2: Deep Link → WebView XSS → Data Exfiltration
```
Detectors: 1 + 2 + existing URL scheme
Crafted deep link opens attacker URL → XSS fires → reads UserDefaults
```

### Chain 3: Deprecated API + Vulnerable SDK → Full RCE
```
Detectors: 1 + 4 + 7 + existing NSCoding
UIWebView + AFNetworking MITM → inject payload → object injection → RCE
```

### Chain 4: Clipboard → Biometric → Keychain → Full Compromise
```
Detectors: 3 + 5 + 6 + existing keychain
Shoulder surf → clipboard steal → session reuse → keychain dump
```

---

## 📊 Complete Usage Example

```bash
# Step 1: Full Static Analysis (includes all 17 detectors)
ioshunt recon com.target.app

# Step 2: Check report for new findings
cat ~/.ioshunt/targets/com.target.app/latest/report.md

# Expected new findings:
# - "CRITICAL: WKWebView JavaScript Bridge Injection"
# - "HIGH: Missing Privacy Manifest (PrivacyInfo.xcprivacy)"
# - "HIGH: Biometric Auth Without Passcode Fallback"
# - "HIGH: Deprecated UIWebView Usage"
# - "HIGH: Sensitive Data Clipboard Exposure"
# - "MEDIUM: Missing App Snapshot Protection"
# - "HIGH: Vulnerable/Misconfigured SDK (AFNetworking < 3.0)"

# Step 3: Dynamic Verification
ioshunt attach com.target.app --url-scheme-monitor --keychain-monitor

# Step 4: AI-Powered Analysis
ioshunt analyze com.target.app

# Step 5: Generate Report
ioshunt report com.target.app --format html
```

---

## 📁 Files Modified

```
Modified:
  core/recon.go        (+510 LOC) — 7 new detector functions + pipeline integration
  core/update.go       — Version bump to v1.15.0

Updated Documentation:
  CHANGELOG.md         — v1.14.2 + v1.15.0 entries
  ATTACK_SCENARIOS.md  — 3 new + 4 chained attack scenarios
  IMPLEMENTATION_COMPLETE.md — Updated with all phases
  NEW_FEATURES_DOCUMENTATION.md — This file
  TEST_NEW_FEATURES.sh — Updated test procedures
  README.md            — Updated features and version
```

---

**Status**: ✅ **ALL 7 DETECTORS IMPLEMENTED AND INTEGRATED**

Ready for bug bounty hunting on iOS applications!
