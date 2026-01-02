# MalSpectra Quick Start Guide

## 🚀 Getting Started

### Installation

```bash
# Clone or navigate to MalSpectra
cd "/path/to/MalSpectra"

# Activate virtual environment
source venv/bin/activate

# Run MalSpectra
python3 main.py
```

---

## 📋 Available Modules

### ✅ Module 1: Reverse Engineering
**Status**: Fully Functional  
**Purpose**: Static malware analysis

**Features**:
- PE file header analysis
- Security feature detection (ASLR, DEP, CFG, SafeSEH)
- Entropy calculation (packed/encrypted detection)
- Import table analysis
- Disassembly with anti-debug pattern detection

**Usage**:
1. Select Option 1 from main menu
2. Enter path to PE file
3. View comprehensive analysis

**Example**:
```
Target: /home/user/malware.exe
```

---

### ✅ Module 2: Ghidra Bridge
**Status**: Fully Functional  
**Purpose**: Automated Ghidra analysis

**Requirements**:
- Ghidra installed (https://ghidra-sre.org/)
- Java JDK 11+ installed

**Features**:
- Headless Ghidra analysis
- Function analysis (name, address, size, parameters)
- String extraction
- Automated script generation
- JSON output parsing

**Setup** (First-time only):
1. Select Option 2 from main menu
2. Choose "Configure Ghidra Path"
3. Enter path to `analyzeHeadless` script
   - Linux: `/opt/ghidra/support/analyzeHeadless`
   - macOS: `/Applications/ghidra/support/analyzeHeadless`
   - Windows: `C:\ghidra\support\analyzeHeadless.bat`

**Usage**:
1. Select Option 2 from main menu
2. Choose "Run Analysis"
3. Enter target binary path
4. Select analysis type:
   - Function Analysis
   - String Extraction
5. View results in table format

---

### ✅ Module 3: Dynamic Sandbox
**Status**: Fully Functional  
**Purpose**: Behavioral malware analysis

**⚠️ CRITICAL WARNING**: 
- **RUN ONLY IN VIRTUAL MACHINE**
- **DO NOT RUN ON HOST SYSTEM**
- **EXECUTES POTENTIALLY MALICIOUS CODE**

**Requirements**:
- Virtual Machine (VirtualBox, VMware, KVM)
- Isolated network
- VM snapshot capability

**Features**:
- Process creation/termination monitoring
- File system change detection
- Network connection monitoring
- Timeout protection
- Comprehensive behavior reports

**Usage**:
1. **Ensure you're in a VM** (take snapshot first!)
2. Select Option 3 from main menu
3. Read safety warning carefully
4. Type "YES" to confirm VM environment
5. Enter path to suspicious file
6. Set execution timeout (default: 10s)
7. Press Enter to execute
8. Review behavior report

**Safe Testing**:
```bash
# Use included test malware (100% safe)
Target: data/test_malware_safe.py
Timeout: 10
```

---

## 🧪 Testing Modules

### Test Module 1 (Reverse Engineering)
```bash
# Use any PE file
Target: /usr/bin/ls  # On Windows systems
Target: data/test_binary.exe  # If you have test samples
```

### Test Module 2 (Ghidra Bridge)
```bash
# After configuring Ghidra path
Target: /bin/ls  # Any binary
Analysis: Function Analysis
```

### Test Module 3 (Sandbox)
```bash
# ONLY IN VM!
Target: data/test_malware_safe.py
Timeout: 10
```

---

## 📊 Understanding Reports

### Reverse Engineering Report
- **File Info**: Size, type, architecture
- **Headers**: DOS, File, Optional headers
- **Security**: ASLR, DEP, CFG, SafeSEH, NX
- **Entropy**: Packing/encryption indicator
  - 🟢 < 6.5: Normal
  - 🟡 6.5-7.0: Suspicious
  - 🔴 > 7.0: Packed/Encrypted
- **Imports**: DLL and function imports
- **Disassembly**: Entry point instructions

### Ghidra Bridge Report
- **Function**: Function name
- **Address**: Entry point address (hex)
- **Size**: Function size in bytes
- **Params**: Parameter count
- **External**: External function flag
- **Called By**: Number of calling functions

### Sandbox Report
- **Execution Summary**: Time, exit code, timeout status
- **Process Activity**: New processes spawned
- **File Changes**:
  - 🟢 CREATED: New files
  - 🟡 MODIFIED: Changed files
  - 🔴 DELETED: Removed files
- **Network Connections**: Remote endpoints contacted

---

## 🔧 Troubleshooting

### Module 1: Reverse Engineering

**"Not a valid PE file"**
- Ensure file is actually a PE executable
- Check file isn't corrupted
- Verify file path is correct

**"Permission denied"**
- Check file permissions: `chmod +r /path/to/file`
- Ensure you have read access

### Module 2: Ghidra Bridge

**"Ghidra path not configured"**
- Run "Configure Ghidra Path" option
- Verify path points to `analyzeHeadless` script
- Make script executable: `chmod +x /path/to/analyzeHeadless`

**"Analysis timed out"**
- Binary too large (>5 minutes analysis)
- Try smaller binary first
- Check Ghidra is properly installed

**"Java not found"**
- Install Java JDK 11+: `sudo apt install openjdk-11-jdk`
- Verify: `java --version`

### Module 3: Sandbox

**"Permission denied" (network monitoring)**
- Network monitoring requires elevated privileges
- Run with: `sudo python3 main.py`

**"No changes detected"**
- Malware execution too fast
- Increase timeout
- Check malware actually executed

**VM not running**
- Verify you're in a VM: `sudo dmidecode -s system-product-name`
- Should show: VirtualBox, VMware, QEMU, etc.

---

## 📚 Documentation

Detailed documentation available in `docs/wiki/`:

- `01_Reverse_Engineering.md` - Module 1 details
- `02_Ghidra_Bridge.md` - Module 2 details
- `03_Malware_Sandbox.md` - Module 3 details (READ SAFETY WARNINGS!)

---

## 🛡️ Safety Guidelines

### Module 1 (Reverse Engineering)
- ✅ Safe to use on any system
- ✅ No code execution
- ✅ Static analysis only

### Module 2 (Ghidra Bridge)
- ✅ Safe to use on any system
- ✅ No direct malware execution
- ✅ Ghidra runs in isolated project

### Module 3 (Sandbox)
- ⚠️ **DANGEROUS - VM ONLY**
- ⚠️ Take VM snapshot before use
- ⚠️ Isolate network
- ⚠️ Never run on host
- ⚠️ Can execute real malware

---

## 🎯 Typical Workflow

### Basic Analysis
```
1. Static Analysis (Module 1)
   ↓
2. Function Analysis (Module 2)
   ↓
3. Behavioral Analysis (Module 3) [VM ONLY]
```

### Step-by-Step Example
```
1. Run Module 1 on suspicious.exe
   - Check entropy (packed?)
   - Review imports (suspicious APIs?)
   - Check security features

2. Run Module 2 on suspicious.exe
   - Extract functions
   - Identify interesting functions
   - Look for malicious patterns

3. Run Module 3 on suspicious.exe (IN VM!)
   - Observe runtime behavior
   - Check file/network activity
   - Confirm malicious intent
```

---

## 📞 Support

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com

**Issues**:
- Check documentation in `docs/wiki/`
- Review troubleshooting sections
- Check logs in `logs/malspectra.log`

---

## 🔄 Quick Commands

```bash
# Start MalSpectra
source venv/bin/activate && python3 main.py

# View logs
tail -f logs/malspectra.log

# Test sandbox safely
# Option 3 → YES → data/test_malware_safe.py → 10 seconds

# Check git status
git log --oneline -5
```

---

## ⚡ Tips & Tricks

1. **Always use Module 1 first** - Static analysis is safe and fast
2. **Take VM snapshots** - Before ANY sandbox testing
3. **Start with safe test** - Use `test_malware_safe.py` first
4. **Read logs** - Check `logs/malspectra.log` for details
5. **Document findings** - Save reports for future reference

---

**Version**: 1.0  
**Last Updated**: $(date +%Y-%m-%d)  
**Status**: Production Ready ✅
