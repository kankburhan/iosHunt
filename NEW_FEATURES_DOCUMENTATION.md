# iOSHunt Security Enhancement - New Features Summary

## Overview
Added **5 advanced security detection features** untuk mengidentifikasi vulnerability patterns yang sebelumnya tidak terdeteksi. Fitur-fitur baru fokus pada exploitation attack surfaces yang accessible langsung oleh user.

---

## 📋 New Features Implemented

### **FEATURE 1: Insecure Deserialization (NSCoding) Detector**
**File**: `core/recon.go:758-798` | **Function**: `AnalyzeNSCodingSecurity()`

#### What It Detects:
- ✅ Unsafe `initWithCoder` tanpa NSSecureCoding
- ✅ `NSKeyedUnarchiver` tanpa `allowedClasses` restriction
- ✅ Legacy deprecated `unarchiveObjectWithData`
- ✅ Custom object deserialization vulnerabilities

#### Why It Matters:
**Object Injection / RCE via Serialized Data**
```
Risk: Attacker dapat create malicious plist/serialized object
      yang akan di-deserialize oleh vulnerable app
Impact: Remote Code Execution, data exfiltration

Real Example:
- Banking app stores user data dengan NSCoding
- Attacker modifies plist di Documents folder
- App deserializes → arbitrary code execution
```

#### How User Can Exploit:
```bash
# 1. Find apps using unsafe deserialization
ioshunt recon com.vulnerable.app

# 2. Look for "Unsafe NSCoding" findings in report
# 3. Use Frida to hook deserialization endpoints
ioshunt attach com.vulnerable.app --nscoding-monitor

# 4. Craft malicious plist and inject via file access
# 5. Trigger app to deserialize → RCE
```

---

### **FEATURE 2: Keychain Sharing Attack Surface Analysis**
**File**: `core/recon.go:804-840` | **Function**: `AnalyzeKeychainSharingRisks()`

#### What It Detects:
- ✅ Insecure `kSecAttrAccessGroup` configurations
- ✅ Wildcard keychain sharing (`*`)
- ✅ Team ID-based keychain access
- ✅ Cross-app keychain sharing risks
- ✅ App groups + Keychain combination

#### Vulnerability Categories:

| Risk Level | Pattern | Impact |
|---|---|---|
| **CRITICAL** | Wildcard `*` in keychain-access-groups | ANY app can steal keychain items |
| **HIGH** | `group.*` sharing | Other group apps access keychain |
| **HIGH** | Team ID sharing | All apps from same team access data |
| **MEDIUM** | App groups enabled | Extensions can intercept keychain |

#### Real Attack Scenario:
```
Target: Uber-like app storing auth tokens
Vulnerability: Keychain shared via app group "group.com.company"

1. Attacker creates dummy app with same group
2. Installs both apps on victim's device
3. Attacker app reads keychain → steals auth token
4. Uses token to access victim's account

Frida Detection:
ioshunt attach uber --keychain-monitor
→ Shows all keychain operations & access groups
```

#### User Exploitation:
```bash
# 1. Check for keychain sharing vulnerabilities
ioshunt recon com.target.app

# 2. Monitor keychain access at runtime
ioshunt attach com.target.app --keychain-monitor

# 3. Output shows all sensitive data being stored
# 4. Create malicious app with same access group
# 5. Read keychain items programmatically
```

---

### **FEATURE 3: Custom URL Scheme Input Validation Analysis**
**File**: `core/recon.go:846-904` | **Function**: `AnalyzeURLSchemeValidation()`

#### What It Detects:
- ✅ URL scheme handlers without input validation
- ✅ Auth-related schemes (`oauth://`, `auth://`)
- ✅ Missing host whitelist validation
- ✅ Parameter injection vulnerabilities
- ✅ Deep link hijacking surfaces

#### Attack Vectors:

**Vector 1: Parameter Injection**
```
App registers: myapp://action?token=XXX&user=YYY

Attacker crafts: myapp://action?token=admin&user=hacked
→ App processes without validation
→ Priv escalation / account takeover
```

**Vector 2: Authentication Bypass**
```
App has: oauth://callback?code=AUTH_CODE

Attacker intercepts:
oauth://callback?code=ATTACKER_CODE
→ Auth bypass, user impersonation
```

**Vector 3: Deep Link Injection**
```
App has: myapp://login?username=admin

Attacker sends via SMS/email:
myapp://login?username=admin
→ Auto-login with admin account
```

#### User Can Find via Frida:
```bash
# Monitor all URL scheme invocations
ioshunt attach instagram --url-scheme-monitor

# Output shows:
# [URL_SCHEME] URL Scheme Called:
#   Scheme: instagram://
#   Full URL: instagram://profile/2818151357?access_token=...
#   [!] SUSPICIOUS: Possible SQL injection in URL
#   [!] WARNING: Sensitive data in URL scheme
```

---

### **FEATURE 4: Background Activity & Data Leak Detection**
**File**: `core/recon.go:910-940` | **Function**: `DetectBackgroundActivityLeaks()`

#### What It Detects:
- ✅ Background URLSession configuration
- ✅ Background data synchronization
- ✅ Sensitive API calls in background
- ✅ Background fetch with PII

#### Real Attack Scenario:
```
Target: Finance app with background sync

Vulnerability:
- App syncs account data in background
- No encryption on sensitive endpoints
- Attacker on same WiFi intercepts data

Steps:
1. User opens app once
2. App enables background sync
3. Later, user closes app
4. App still syncs data every 15 minutes
5. Attacker intercepts → account info stolen
```

#### Exploitation:
```bash
# Detect which background operations are happening
ioshunt attach finance-app

# Frida hooks show:
# [Background Data Sync] Syncing to: api.finance.com/sync
# - Sending: account_number, balance, transactions
# → NO encryption beyond TLS
```

---

### **FEATURE 5: App Extension & Shared Container Security**
**File**: `core/recon.go:946-970` | **Function**: `AnalyzeAppExtensionSecurity()`

#### What It Detects:
- ✅ Insecure app groups usage
- ✅ WidgetKit security risks
- ✅ Shared container vulnerabilities
- ✅ Inter-process communication risks

#### Attack Scenario:
```
Target: Banking app dengan share widget

Vulnerability:
- Widget shares data via app group
- Other apps in group can read shared container
- Widget shows account balance on lock screen

Attack:
1. Attacker app registers for same app group
2. Reads shared container at any time
3. Sees account balance, recent transactions
4. Uses information for phishing/fraud
```

---

## 🔍 Dynamic Analysis (Frida Hooks)

### **New Frida Scripts Added:**

#### 1. `url_scheme_monitor.js` 🔗
```bash
ioshunt attach AppName --url-scheme-monitor

Monitors:
✓ All URL scheme invocations
✓ Parameter validation checks
✓ SQL injection in URL params
✓ JavaScript injection attempts
✓ Sensitive data leakage
```

**Example Output:**
```
[URL_SCHEME] URL Scheme Called:
  Scheme: myapp://
  Full URL: myapp://action?token=abc123
  [!] SUSPICIOUS: Possible SQL injection in URL

[!!] WARNING: Sensitive data in URL scheme
  Pattern: token=
  URL: myapp://action?token=eyJhbGc...
```

#### 2. `nscoding_monitor.js` 📦
```bash
ioshunt attach AppName --nscoding-monitor

Monitors:
✓ Object deserialization calls
✓ Unsafe unarchiveObjectWithData usage
✓ NSKeyedUnarchiver without allowedClasses
✓ Plist loading from untrusted sources
✓ Object injection attempts
```

**Example Output:**
```
[!] CRITICAL: Unsafe unarchiveObjectWithData called!
  Method: NSKeyedUnarchiver.unarchiveObjectWithData
  Vulnerability: Can deserialize ANY object type
  Risk: Object Injection / Remote Code Execution

[KEYCHAIN_ADD] Storing item with custom access group:
  Service: auth_token
  Access Group: group.com.company
  [!] WARNING: App group sharing enabled
```

#### 3. `keychain_security_monitor.js` 🔐
```bash
ioshunt attach AppName --keychain-monitor

Monitors:
✓ Keychain item storage operations
✓ Access group configurations
✓ Keychain sharing patterns
✓ Sensitive data in keychain
✓ App group container access
```

**Example Output:**
```
[KEYCHAIN_ADD] Storing item with custom access group:
  Service: authentication_token
  Access Group: group.com.company *
  Access Level: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  [!!!] CRITICAL: Wildcard access group - accessible by ANY app!

[APP_GROUP] Accessing shared container:
  Group ID: group.com.company
  [!] Data shared with app extensions/other apps!
```

---

## 📊 Usage Examples

### **Complete Scanning Workflow:**

```bash
# Step 1: Static Analysis
ioshunt recon com.target.app

# Step 2: Check vulnerable patterns in report
# Look for:
# - "Unsafe NSCoding"
# - "Keychain Shared via App Groups"
# - "Unvalidated URL Scheme Handler"
# - "Potential Background Data Leak"
# - "App Extension Shared Container"

# Step 3: Runtime Analysis - Exploit the vulnerabilities
ioshunt attach com.target.app \
  --nscoding-monitor \
  --url-scheme-monitor \
  --keychain-monitor

# Step 4: Trigger vulnerable code paths
# - Interact with app normally
# - Follow custom deep links
# - Sync data in background
# - Access widgets

# Step 5: Analyze Frida output for:
# - Sensitive data exposure
# - Missing input validation
# - Unsafe deserialization calls
# - Keychain sharing patterns
```

### **Targeted Exploitation Example:**

```bash
# Find banking app vulnerabilities
ioshunt recon com.mybank.mobile

# Result: Found "Unvalidated URL Scheme Handler: mybank://"
# Now exploit:
ioshunt attach com.mybank.mobile --url-scheme-monitor

# In another terminal, trigger:
xcrun simctl openurl booted "mybank://login?user=admin&bypass=true"

# Frida intercepts & shows validation issues:
# [URL_SCHEME] URL Scheme Called:
#   URL: mybank://login?user=admin&bypass=true
#   [!] SUSPICIOUS: No validation detected
#   → App processes directly!
```

---

## 🎯 Security Implications - What Developers MISSED

| Feature | Vulnerability | Without Detection | With Detection |
|---------|---|---|---|
| NSCoding | RCE via deserialization | Hidden risk | **FOUND: Object Injection** |
| Keychain | Cross-app data theft | Silent vulnerability | **FOUND: *wildcard access** |
| URL Scheme | Deep link injection | Simple attacks succeed | **FOUND: No validation** |
| Background | PII leakage | Invisible in static analysis | **FOUND: Sensitive sync** |
| App Groups | Widget data interception | Not obvious | **FOUND: Shared container** |

---

## 📁 Files Modified/Created

```
Modified:
  - core/recon.go
    * Added 3 hardening signatures
    * Added 5 new analysis functions

  - cmd/attach.go
    * Added 3 new Frida script flags

Created:
  - assets/url_scheme_monitor.js (170 lines)
  - assets/nscoding_monitor.js (180 lines)
  - assets/keychain_security_monitor.js (190 lines)
```

---

## 🚀 Key Improvements Summary

| # | Detection | Severity | Exploitability | User Access |
|---|---|---|---|---|
| 1 | Unsafe NSCoding | CRITICAL | High (RCE) | Frida hook |
| 2 | Keychain Wildcard | CRITICAL | High (theft) | Frida hook |
| 3 | Unvalidated URL Scheme | HIGH | High (injection) | Frida hook |
| 4 | Background Data Leak | HIGH | Medium (MITM) | Static + Frida |
| 5 | App Group Sharing | HIGH | High (intercept) | Static + Frida |

---

## 💡 Future Enhancements Could Include:

- GraphQL injection detection
- Type confusion vulnerability detection
- JIT compilation security analysis
- WebRTC vulnerability scanning
- Siri Intent handler security checking
- CloudKit security analysis
- Property list injection detection
- Insecure deserialization in Swift (Codable)
- Sensitive Swift memory operations
- Swizzling/method hooking detection

---

## 📝 Testing Checklist

To verify new features work correctly:

```bash
# 1. Build and run iOSHunt
go build -o ioshunt

# 2. Test static analysis
./ioshunt recon com.test.app
# Verify: New findings appear in report.json

# 3. Test Frida hooks
./ioshunt attach com.test.app --nscoding-monitor
# Verify: Script loads and hooks initialize

./ioshunt attach com.test.app --url-scheme-monitor
# Verify: URL scheme calls are intercepted

./ioshunt attach com.test.app --keychain-monitor
# Verify: Keychain operations are logged

# 4. Analyze output
# Check report.md for:
# - "Unsafe NSCoding (Possible Object Injection)"
# - "Keychain Shared via App Groups"
# - "Unvalidated URL Scheme Handler"
# - "Potential Background Data Leak"
# - "App Extension Shared Container"
```

---

**Status**: ✅ **ALL FEATURES IMPLEMENTED AND INTEGRATED**

Ready for security testing against iOS applications!
