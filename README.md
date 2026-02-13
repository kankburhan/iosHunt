# iOSHunt

**One Command iOS Pentesting Pipeline**

`ioshunt` is a comprehensive CLI tool designed to automate the entire lifecycle of an iOS application security assessment. From downloading the IPA to advanced runtime analysis, it handles the tedious setup so you can focus on finding vulnerabilities.

## 🚀 Features (v1.0.0)

### 1. Automation Pipeline
-   **Download**: Fetches IPAs from the App Store (handles auth & country selection).
-   **Injection**: Automatically inserts `FridaGadget.dylib`.
-   **Resigning**: Resigns the app with your development profile.
-   **Installation**: Deploys to connected devices via `ios-deploy`.

### 2. Static Analysis (Recon)
-   **Secrets Scanning**: Detects hardcoded keys, tokens, and private data using custom regex templates.
-   **Misconfigurations**: Checks for insecure `Info.plist` settings (ATS, File Sharing) and Entitlements (`get-task-allow`).
-   **Binary Security**: Verifies PIE, ARC, Stack Canaries, and Encryption status.
-   **Reporting**: Generates JSON and HTML reports (`ioshunt report`).

### 3. Dynamic Analysis (Runtime)
-   **Frida Integration**: Attaches to running processes with a single command.
-   **Bypasses**: Built-in scripts for **SSL Pinning**, **Biometrics**, **Jailbreak Detection**, and **iXGuard/Anti-Debugging**.
-   **Forensics**: Dumps **Keychain**, **Cookies**, and **NSUserDefaults** (`ioshunt dump`).
-   **Monitoring**: Logs crypto operations (`CCCrypt`, `SecKey`) and HTTP headers (`Authorization`) in real-time.

### 4. Utilities
-   **Update**: Self-updating via `ioshunt update`.
-   **Doctor**: Verifies environment health and dependencies.
-   **Clean**: Manages and cleans up workspace data.

## 🛠 Installation

### Prerequisites
-   macOS (Required for `codesign`, `security`)
-   Go 1.21+
-   `frida`, `objection`, `ideviceinstaller`, `ios-deploy`

### Build from Source
```bash
git clone https://github.com/mburhan/ioshunt.git
cd ioshunt
go install
```

## 📖 Usage

### Full Pipeline
Run the complete workflow (Download -> Inject -> Resign -> Install -> Attach):
```bash
ioshunt com.example.app
```

### Static Analysis
```bash
# Analyze a target and generate an HTML report
ioshunt recon com.example.app
ioshunt report com.example.app --format html
```

### Runtime Analysis
```bash
# Attach with SSL Pinning and Jailbreak Bypass
ioshunt attach "App Name" --ssl --bypass

# Monitor Crypto Operations and Headers
ioshunt attach "App Name" --crypto --headers
```

### Forensics
```bash
# Dump Keychain Items
ioshunt dump keychain com.example.app

# Dump Cookies
ioshunt dump cookies com.example.app
```

### Maintenance
```bash
# Check environment
ioshunt doctor

# Update tool
ioshunt update
```

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License
MIT

