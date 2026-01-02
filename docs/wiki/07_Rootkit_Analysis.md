# Module 7: Rootkit Analysis Suite

## Overview

The Rootkit Analysis Suite is a comprehensive system integrity scanner that detects hidden system artifacts and rootkit indicators on Linux systems. Rootkits are malicious software designed to hide the presence of certain processes or programs from normal methods of detection, enabling persistent unauthorized access to a computer.

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Status**: Production Ready ⚠️ ROOT RECOMMENDED

---

## What is a Rootkit?

### Definition

A **rootkit** is a collection of software tools that enable unauthorized users to gain control of a computer system without being detected. Rootkits can:

- Hide processes and files
- Conceal network connections
- Intercept system calls
- Modify kernel behavior
- Maintain persistent backdoor access

### Types of Rootkits

1. **User-mode Rootkits**: Operate at application level
2. **Kernel-mode Rootkits**: Operate at kernel level (most dangerous)
3. **Bootloader Rootkits**: Infect boot process
4. **Firmware Rootkits**: Infect device firmware

---

## Features

- **Hidden Process Detection**: Compare `/proc` entries with `psutil` visibility
- **LD_PRELOAD Hook Detection**: Identify suspicious library preloading
- **Promiscuous Mode Detection**: Detect network sniffing capabilities
- **Colored Output**: Green for clean, red for infected
- **Comprehensive Reports**: Detailed system integrity assessment
- **Privilege Detection**: Warns when not running as root

---

## Technical Details

### Components

#### 1. detector.py (RootkitDetector Class)

**Purpose**: Core detection engine

**Key Methods**:

- `check_hidden_processes()`: Detect process hiding
- `check_ld_preload()`: Detect library hooks
- `check_promiscuous_mode()`: Detect network sniffing
- `run_all_checks()`: Execute complete scan

#### 2. main.py (User Interface)

**Purpose**: Interactive system scanner

**Features**:
- Rich terminal UI with colored output
- Tabular data presentation
- Threat level indicators
- Actionable recommendations

---

## Detection Techniques

### 1. Hidden Process Detection

**How it Works**:

```
1. Read PIDs from /proc directory
   ↓
2. Read PIDs from psutil library
   ↓
3. Compare the two sets
   ↓
4. PIDs in /proc but not in psutil = HIDDEN
```

**Example**:

```python
# Get PIDs from /proc
proc_pids = set()
for entry in os.listdir('/proc'):
    if entry.isdigit():
        proc_pids.add(int(entry))

# Get PIDs from psutil
psutil_pids = set(p.pid for p in psutil.process_iter(['pid']))

# Find hidden PIDs
hidden = proc_pids - psutil_pids
```

**Why This Works**:

User-mode rootkits often hook libraries like libc or procps to hide processes from tools like `ps`, `top`, and `psutil`. However, they can't hide the `/proc/<PID>` directory itself without kernel-level access. This discrepancy reveals hidden processes.

**Limitations**:

- Kernel-mode rootkits can hide from both methods
- Requires root to access all `/proc/<PID>` directories
- Short-lived processes may cause false positives

---

### 2. LD_PRELOAD Hook Detection

**What is LD_PRELOAD?**

`LD_PRELOAD` is a Linux mechanism that allows custom shared libraries to be loaded before all others. This can be used legitimately (debugging, testing) or maliciously (hooking system calls).

**Malicious Use**:

```c
// Malicious hook example
int open(const char *pathname, int flags, ...) {
    // Hide specific files
    if (strstr(pathname, "backdoor") != NULL) {
        errno = ENOENT;
        return -1;  // File not found
    }
    // Call original open()
    return original_open(pathname, flags);
}
```

**Detection Locations**:

1. **`/etc/ld.so.preload` file**: System-wide preload configuration
2. **`LD_PRELOAD` environment variable**: Per-process preloading
3. **`LD_LIBRARY_PATH` environment variable**: Library search paths

**Suspicious Indicators**:

- Libraries with names like: `hook`, `inject`, `hide`, `stealth`
- Libraries in temporary directories: `/tmp`, `/dev/shm`
- Unknown or obfuscated library names

**Detection Code**:

```python
# Check /etc/ld.so.preload
if os.path.exists('/etc/ld.so.preload'):
    with open('/etc/ld.so.preload', 'r') as f:
        content = f.read()
        # Check for suspicious patterns
        
# Check environment
ld_preload = os.environ.get('LD_PRELOAD', '')
if ld_preload:
    # Analyze preloaded libraries
```

---

### 3. Promiscuous Mode Detection

**What is Promiscuous Mode?**

Network interfaces normally only process packets destined for their MAC address. **Promiscuous mode** allows an interface to capture ALL packets on the network segment, enabling packet sniffing.

**Malicious Use**:

- Password sniffing
- Session hijacking
- Network traffic analysis
- Credential theft

**Detection Method**:

Uses the `ioctl` system call with `SIOCGIFFLAGS` to read interface flags:

```python
import socket
import fcntl
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# SIOCGIFFLAGS = 0x8913 (get interface flags)
flags = fcntl.ioctl(
    sock.fileno(),
    0x8913,
    struct.pack('256s', iface_name.encode())
)

flags_value = struct.unpack('H', flags[16:18])[0]

# IFF_PROMISC = 0x100
is_promisc = bool(flags_value & 0x100)
```

**Interface Flags**:

- `IFF_UP` (0x1): Interface is up
- `IFF_BROADCAST` (0x2): Broadcast address valid
- `IFF_LOOPBACK` (0x8): Loopback interface
- **`IFF_PROMISC` (0x100): Promiscuous mode** ← We check this

**Legitimate Uses**:

- Network monitoring tools (Wireshark, tcpdump)
- IDS/IPS systems
- Network troubleshooting

**Requires Root**: Checking interface flags typically requires elevated privileges.

---

## Usage

### Prerequisites

```bash
# Install dependencies (already in requirements.txt)
pip install psutil rich

# Run as root for full functionality
sudo python3 main.py
```

### Basic Workflow

```bash
# 1. Start MalSpectra
python3 main.py

# 2. Select Module 7 (Rootkit Analysis)

# 3. View system integrity report

# 4. Review findings and recommendations
```

### Example Session

```
═══ ROOTKIT ANALYSIS SUITE ═══
System Integrity Scanner

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com

⚠ Not running as root
Some checks may be limited without root privileges

Initializing rootkit detector...
✓ Detector ready

Scanning system for rootkit indicators...
✓ Scan complete

════════════════════════════════════════════════════════

═══ SCAN RESULTS ═══

1. Hidden Processes Check
✓ CLEAN - No hidden processes detected

2. LD_PRELOAD Hooks Check
✓ CLEAN - No LD_PRELOAD hooks detected

3. Promiscuous Mode Check
✓ CLEAN - No promiscuous interfaces detected

════════════════════════════════════════════════════════

╔═══════════════════════════════════════╗
║   System Integrity Report             ║
╠═══════════════════════════════════════╣
║ SYSTEM STATUS: CLEAN                  ║
║                                       ║
║ No rootkit indicators detected.       ║
║ System appears to be healthy.         ║
╚═══════════════════════════════════════╝
```

### Infected System Example

```
1. Hidden Processes Check
✗ INFECTED - 2 hidden process(es) detected

┏━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ PID  ┃ Command Line     ┃ Threat Level┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 1337 │ /tmp/.backdoor   │ HIGH        │
│ 9999 │ /dev/shm/.miner  │ HIGH        │
└──────┴──────────────────┴─────────────┘

2. LD_PRELOAD Hooks Check
✗ SUSPICIOUS - 1 suspicious hook(s) detected

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Location            ┃ Library         ┃ Threat Level┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ /etc/ld.so.preload  │ /tmp/libhook.so │ CRITICAL    │
└─────────────────────┴─────────────────┴─────────────┘

╔═══════════════════════════════════════╗
║   System Integrity Report             ║
╠═══════════════════════════════════════╣
║ SYSTEM STATUS: INFECTED               ║
║                                       ║
║ Rootkit activity detected!            ║
║ Immediate action required.            ║
╚═══════════════════════════════════════╝

Recommended Actions:

  • Investigate hidden processes immediately
    → Use: ps aux, top, lsof -p <PID>
    → Check: /proc/<PID>/exe, /proc/<PID>/maps

  • Review LD_PRELOAD hooks
    → Examine: /etc/ld.so.preload
    → Check library authenticity with: ldd, strings

  • General recommendations:
    → Run rkhunter or chkrootkit
    → Check system logs: /var/log/syslog
    → Verify system files: rpm -Va or debsums
    → Consider reinstalling from known good media
```

---

## Use Cases

### 1. Security Auditing
Regular system integrity checks as part of security policy.

### 2. Incident Response
Investigate suspected compromises and rootkit infections.

### 3. Forensic Analysis
Gather evidence of system modifications and hidden artifacts.

### 4. Compliance
Demonstrate system integrity for regulatory requirements.

### 5. Research
Study rootkit techniques and detection methods.

---

## Detection Accuracy

### True Positives ✓

- Hidden malware processes
- Malicious LD_PRELOAD hooks
- Unauthorized packet sniffing

### False Positives ⚠

- Legitimate debugging tools
- Docker/container processes
- Development environments with custom library paths
- Network monitoring in legitimate scenarios

### False Negatives ✗

- Kernel-mode rootkits (sophisticated)
- BIOS/firmware rootkits
- Zero-day rootkit techniques
- Properly designed stealth malware

---

## Advanced Techniques

### Custom Detection Rules

Extend the `RootkitDetector` class:

```python
class CustomDetector(RootkitDetector):
    def check_kernel_modules(self):
        """Check for suspicious kernel modules"""
        suspicious = []
        with open('/proc/modules', 'r') as f:
            for line in f:
                module = line.split()[0]
                if any(s in module.lower() for s in ['hide', 'root', 'backdoor']):
                    suspicious.append(module)
        return suspicious
```

### Integration with Other Tools

```bash
# Run rkhunter after MalSpectra scan
sudo rkhunter --check --skip-keypress

# Run chkrootkit
sudo chkrootkit

# Check system files
sudo rpm -Va  # RedHat/CentOS
sudo debsums -c  # Debian/Ubuntu
```

---

## Limitations

### Technical Limitations

- **Kernel Rootkits**: Cannot detect sophisticated kernel-level hiding
- **Root Required**: Full detection needs root privileges
- **Platform Specific**: Linux-only detection methods
- **Snapshot in Time**: Only detects current state, not historical activity

### Detection Gaps

- **Novel Techniques**: New rootkit methods may bypass detection
- **VM Detection**: Rootkit may detect virtual environment
- **Anti-Forensics**: Sophisticated malware can evade analysis

---

## Troubleshooting

### "Permission denied" Errors

**Cause**: Not running as root  
**Solution**: Run with sudo for full functionality

```bash
sudo python3 main.py
```

### "No module named 'psutil'"

**Cause**: Missing dependency  
**Solution**: Install psutil

```bash
pip install psutil
```

### Many False Positives in Development Environment

**Cause**: Docker, debuggers, custom tools  
**Solution**: Filter known-good processes and libraries

### Cannot Check Promiscuous Mode

**Cause**: Requires root or special permissions  
**Solution**: Run as root or grant CAP_NET_ADMIN capability

---

## Best Practices

### 1. Regular Scans
Run rootkit scans weekly or after suspicious activity.

### 2. Baseline Creation
Create clean system baseline for comparison.

### 3. Multi-Tool Approach
Use multiple detection tools (rkhunter, chkrootkit, AIDE).

### 4. Kernel Integrity
Use kernel module signing and verified boot.

### 5. File Integrity Monitoring
Implement AIDE or Tripwire for file system monitoring.

### 6. Log Analysis
Correlate findings with system logs.

### 7. Network Monitoring
Use IDS/IPS alongside rootkit detection.

---

## Comparison with Other Tools

| Feature | MalSpectra | rkhunter | chkrootkit | AIDE |
|---------|------------|----------|------------|------|
| Hidden Processes | ✓ | ✓ | ✓ | ✗ |
| LD_PRELOAD Detection | ✓ | ✓ | ✓ | ✗ |
| Promiscuous Mode | ✓ | ✓ | ✓ | ✗ |
| File Integrity | ✗ | ✓ | Limited | ✓ |
| Kernel Module Check | ✗ | ✓ | ✓ | ✗ |
| Rich UI | ✓ | ✗ | ✗ | ✗ |
| Educational Focus | ✓ | ✗ | ✗ | ✗ |

---

## References

- **Linux Rootkits**: https://www.kernel.org/doc/Documentation/security/
- **rkhunter**: http://rkhunter.sourceforge.net/
- **chkrootkit**: http://www.chkrootkit.org/
- **AIDE**: https://aide.github.io/
- **Rootkit Arsenal**: Book by Bill Blunden
- **Linux Kernel Security**: https://www.kernel.org/doc/html/latest/security/

---

## Technical Background

### Process Hiding Techniques

1. **DKOM (Direct Kernel Object Manipulation)**: Modify kernel data structures
2. **Library Hooking**: Intercept libc functions (readdir, stat)
3. **Procfs Manipulation**: Hide `/proc/<PID>` entries
4. **Syscall Hooking**: Redirect system call table

### LD_PRELOAD Deep Dive

```c
// Hook example - hiding processes from ps
DIR *opendir(const char *name) {
    // Get original function
    DIR *(*original_opendir)(const char*);
    original_opendir = dlsym(RTLD_NEXT, "opendir");
    
    // Filter /proc directory
    if (strcmp(name, "/proc") == 0) {
        // Return filtered directory
    }
    
    return original_opendir(name);
}
```

### Network Sniffing

```python
# Set promiscuous mode (requires root)
import socket
import struct
import fcntl

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
sock.bind(("eth0", 0))

# Enable promiscuous mode
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
```

---

## Legal and Ethical Considerations

### Authorized Use Only

- Only scan systems you own or have permission to audit
- Corporate environments require IT approval
- Unauthorized security testing may violate laws

### Responsible Disclosure

- Report findings to appropriate authorities
- Document evidence properly
- Follow responsible disclosure practices

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Rootkit Analysis Suite  
**Version**: 1.0  
**Status**: ⚠️ Production Ready - Use Responsibly
