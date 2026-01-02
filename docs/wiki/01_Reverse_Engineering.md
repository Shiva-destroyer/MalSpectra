# Module 01: Advanced Malware Reverse Engineering Suite

## 📋 Overview

The **Reverse Engineering Suite** is a comprehensive malware analysis toolkit designed for security researchers and malware analysts. It provides automated analysis of Portable Executable (PE) files, extracting critical forensic data to understand malware behavior, structure, and potential threats.

### Key Capabilities

- **PE Header Analysis**: Complete dissection of DOS, File, and Optional headers
- **Security Feature Detection**: Identification of ASLR, DEP, NX, SafeSEH, and CFG
- **Import Analysis**: Extraction and cataloging of DLL dependencies and API calls
- **Entropy Calculation**: Shannon entropy-based detection of packed/encrypted sections
- **Entry Point Disassembly**: Automated disassembly of executable code using Capstone

---

## 🔬 Technical Details

### PE File Structure

A Portable Executable (PE) is the standard executable format for Windows systems. Understanding its structure is critical for malware analysis:

#### 1. **DOS Header**
- Legacy compatibility header
- Contains "MZ" magic signature (0x5A4D)
- Points to the PE header via `e_lfanew` field

#### 2. **PE Headers**

**File Header:**
- Machine type (x86, AMD64, ARM)
- Number of sections
- Timestamp (compilation date)
- Characteristics flags

**Optional Header:**
- Architecture (32-bit or 64-bit)
- Entry point address (where execution begins)
- Image base address (preferred load address)
- Subsystem type (GUI, Console, Native)
- DLL characteristics (security features)

#### 3. **Section Headers**
Each section contains:
- Name (.text, .data, .rdata, etc.)
- Virtual address and size
- Raw data size and offset
- Characteristics (readable, writable, executable)

### Security Features

#### ASLR (Address Space Layout Randomization)
- Randomizes memory addresses of key structures
- Makes exploit development more difficult
- Flag: `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (0x0040)

#### DEP/NX (Data Execution Prevention / No Execute)
- Prevents code execution from data pages
- Hardware-enforced memory protection
- Flag: `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (0x0100)

#### SafeSEH (Safe Structured Exception Handling)
- Validates exception handler chains
- Prevents SEH overwrites
- Flag: `IMAGE_DLLCHARACTERISTICS_NO_SEH` (0x0400) - inverted logic

#### CFG (Control Flow Guard)
- Modern exploit mitigation
- Validates indirect call targets
- Flag: `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (0x4000)

### Shannon Entropy

Shannon entropy measures the randomness/information density of data:

```
H(X) = -Σ P(xi) * log2(P(xi))
```

Where:
- `H(X)` = entropy (0-8 bits)
- `P(xi)` = probability of byte value `i`

**Interpretation:**
- **0.0 - 4.0**: Low entropy (plain text, zeros, patterns)
- **4.0 - 6.5**: Normal entropy (compiled code, structured data)
- **6.5 - 7.0**: Medium entropy (compressed data)
- **7.0 - 8.0**: High entropy (encrypted/packed data, random)

**Malware Detection:**
Sections with entropy > 7.0 are flagged as suspicious because:
1. Legitimate code rarely has such high randomness
2. Packers encrypt/compress code to evade detection
3. Encrypted configuration data or embedded payloads

### Disassembly Analysis

The disassembler uses Capstone to convert machine code to assembly:

#### Architecture Detection
```python
if pe.OPTIONAL_HEADER.Magic == 0x20b:  # PE32+
    arch = x64
else:  # PE32
    arch = x86
```

#### Entry Point Analysis
The entry point is where the loader transfers control. Analyzing the first instructions can reveal:
- **Legitimate software**: Standard compiler prologue (push ebp, mov ebp, esp)
- **Packers**: Jump to unpacking stub, anti-debug checks
- **Malware**: Obfuscated code, API hashing, VM detection

#### Suspicious Patterns
- `int 2dh/int 3`: Debugger detection
- `rdtsc`: Timing-based anti-debug
- `cpuid`: VM/sandbox detection
- Excessive jumps: Control flow obfuscation

---

## 💻 Usage

### Running the Module

1. Launch MalSpectra:
```bash
python main.py
```

2. Select option `1` from the main menu:
```
[1] Reverse Engineering
```

3. Enter the path to the PE file:
```
Target File: /path/to/suspicious.exe
```

4. Review the comprehensive analysis report

### Sample Output Structure

```
📊 FILE INFORMATION
├── Filename
├── Size
└── Path

📋 PE HEADERS ANALYSIS
├── DOS Header (Magic, PE Offset)
├── File Header (Machine, Sections, Timestamp)
└── Optional Header (Architecture, Entry Point, Subsystem)

🔒 SECURITY FEATURES
├── ASLR: ✓ ENABLED
├── DEP/NX: ✓ ENABLED
├── SafeSEH: ✗ DISABLED
├── CFG: ✗ DISABLED
└── Security Score: 2/5

📊 SECTION ENTROPY ANALYSIS
├── .text: 6.234 (SAFE)
├── .rdata: 5.891 (SAFE)
├── .data: 7.823 (CRITICAL - Packed/Encrypted)
└── .rsrc: 6.456 (WARNING - Compressed)

📦 IMPORTED DLLs & FUNCTIONS
├── KERNEL32.dll (45 functions)
├── USER32.dll (23 functions)
└── ADVAPI32.dll (12 functions)

🔍 DISASSEMBLY (Entry Point)
├── Address: 0x401000
├── RVA: 0x1000
└── First 64 bytes disassembled
```

---

## 🧮 Algorithmic Logic

### Entropy Detection Algorithm

```python
def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy to detect packing/encryption.
    
    Algorithm:
    1. Count frequency of each byte value (0-255)
    2. Calculate probability: P(x) = count(x) / total_bytes
    3. Apply Shannon formula: H = -Σ P(x) * log2(P(x))
    4. Return entropy value (0-8)
    """
    
    if not data:
        return 0.0
    
    # Step 1: Frequency analysis
    frequency = defaultdict(int)
    for byte in data:
        frequency[byte] += 1
    
    # Step 2 & 3: Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in frequency.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy
```

### Risk Assessment Logic

```python
if entropy > 7.0:
    risk = "CRITICAL"
    suspicion = "Packed/Encrypted"
elif entropy > 6.5:
    risk = "WARNING"
    suspicion = "Compressed"
else:
    risk = "SAFE"
    suspicion = "Normal"
```

**Rationale:**
- **7.0+ threshold**: Statistical analysis shows legitimate code entropy peaks at ~6.8
- **6.5-7.0 range**: Compressed resources (PNG, JPEG) or compiler optimizations
- **Below 6.5**: Standard compiled code, string tables, structured data

### Import Analysis Strategy

```python
# Categorize imports by risk level
high_risk_functions = [
    'VirtualAllocEx',    # Process injection
    'WriteProcessMemory', # Code injection
    'CreateRemoteThread', # Thread injection
    'RegSetValueEx',      # Registry modification
    'URLDownloadToFile'   # Download capability
]

for dll_import in imports:
    for function in dll_import['functions']:
        if function['name'] in high_risk_functions:
            flag_suspicious()
```

---

## ⚠️ Limitations

1. **Packed Malware**: Requires unpacking for full analysis
2. **Obfuscated Code**: May not detect all evasion techniques
3. **64-bit Support**: Limited testing on ARM64 binaries
4. **Non-PE Files**: Only supports Windows PE format

---

## 🔮 Future Enhancements

- [ ] Automatic unpacking for common packers (UPX, ASPack)
- [ ] YARA rule generation from imports
- [ ] String extraction and analysis
- [ ] Resource analysis (icons, manifests)
- [ ] Digital signature verification
- [ ] Behavioral heuristics scoring
- [ ] Export of results to JSON/HTML reports

---

## 📚 References

- Microsoft PE/COFF Specification
- "Practical Malware Analysis" - Sikorski & Honig
- Shannon, C.E. (1948) - "A Mathematical Theory of Communication"
- Capstone Disassembly Framework Documentation
- pefile Library Documentation

---

## 👨‍💻 Developer

**Sai Srujan Murthy**  
📧 saisrujanmurthy@gmail.com

---

*Last Updated: January 3, 2026*
