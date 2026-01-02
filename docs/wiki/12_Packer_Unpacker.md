# Module 12: Malware Packer/Unpacker

**Developer:** Sai Srujan Murthy  
**Contact:** saisrujanmurthy@gmail.com  
**Category:** Binary Analysis | Reverse Engineering

---

## Overview

The **Malware Packer/Unpacker** module provides tools for handling packed and obfuscated malware binaries. It supports UPX (Ultimate Packer for eXecutables) packing/unpacking and PE overlay detection/manipulation. Understanding packing techniques is essential for malware analysis, as ~80% of modern malware uses some form of packing or obfuscation.

### What is Packing?

**Packing** is the process of compressing and/or encrypting an executable to:
- Reduce file size
- Evade signature-based detection
- Hide malicious code from static analysis
- Protect intellectual property

**Legitimate Uses:**
- Software distribution (smaller downloads)
- Anti-piracy protection
- Licensing enforcement

**Malicious Uses:**
- Evade antivirus signatures
- Hide malicious strings/APIs
- Complicate reverse engineering
- Polymorphic malware generation

---

## Packing Fundamentals

### How Packing Works

```
[Original Executable]
        ↓
    [Compress]
        ↓
[Packed Data] + [Decompression Stub]
        ↓ (Runtime)
  [Decompress in Memory]
        ↓
[Original Executable Executes]
```

**Key Components:**

1. **Compressed/Encrypted Data**: Original executable in packed form
2. **Decompression Stub**: Small code that unpacks at runtime
3. **Entry Point Redirection**: Stub executes first, then jumps to original entry point (OEP)

### Entropy Analysis

**Shannon Entropy** indicates randomness:

```
H(X) = -Σ P(xi) × log2(P(xi))
```

**Typical Entropy Values:**

| Content Type | Entropy Range | Example |
|--------------|---------------|---------|
| Plain Text | 3.5 - 4.5 | "Hello World" → 3.8 |
| Executable Code | 5.5 - 6.5 | Normal .exe → 6.2 |
| Compressed (ZIP) | 7.0 - 7.5 | ZIP archive → 7.3 |
| UPX Packed | 7.5 - 7.9 | UPX --best → 7.8 |
| Encrypted (AES) | 7.9 - 8.0 | AES-256 → 7.99 |

**Detection:**
```python
if entropy > 7.5:
    print("Likely packed or encrypted")
```

---

## UPX (Ultimate Packer for eXecutables)

### Overview

**UPX** is the most popular executable packer:
- Open source (GPL)
- Cross-platform (Windows, Linux, macOS)
- Supports multiple formats (PE, ELF, Mach-O)
- Compression ratio: 50-70%
- Fast decompression

**Official Website:** https://upx.github.io/

### Installation

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install upx-ucl
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install upx
```

#### Linux (Arch)
```bash
sudo pacman -S upx
```

#### macOS (Homebrew)
```bash
brew install upx
```

#### Windows (Chocolatey)
```powershell
choco install upx
```

#### Windows (Manual)
```
1. Download from: https://github.com/upx/upx/releases
2. Extract to: C:\Program Files\upx\
3. Add to PATH
```

### UPX Compression Algorithms

UPX supports multiple compression algorithms:

#### **1. NRV (Not Really Vanished)**
- Default algorithm
- Good balance of speed/ratio
- Compression: Fast
- Decompression: Very Fast

#### **2. LZMA (Lempel-Ziv-Markov)**
- Best compression ratio
- Used with `--best` flag
- Compression: Slow
- Decompression: Fast
- Entropy: ~7.8-7.9

#### **3. UCL (Ultimate Compression Library)**
- Fast compression/decompression
- Lower ratio than LZMA
- Good for large files

### Compression Levels

```bash
upx -1 file.exe    # Fastest (70% size, 1 second)
upx -5 file.exe    # Balanced (60% size, 2 seconds)
upx -9 file.exe    # Best compression (50% size, 5 seconds)
upx --best file.exe # Maximum (LZMA, 45% size, 10 seconds)
upx --ultra-brute file.exe # Extreme (40% size, 60 seconds)
```

### UPX Signatures

UPX adds specific signatures to packed files:

#### **PE (Windows) Signatures**

**Section Names:**
- `UPX0`: Empty section (to be filled with unpacked code)
- `UPX1`: Compressed data
- `UPX2`: (optional) Additional data

**Magic Bytes:**
```
Offset 0x00: "MZ" (DOS header)
Offset varies: "UPX!" (UPX signature)
Offset varies: "UPX0", "UPX1" in section headers
```

**Detection Code:**
```python
with open('file.exe', 'rb') as f:
    data = f.read(4096)
    signatures = [b'UPX!', b'UPX0', b'UPX1', b'UPX2']
    for sig in signatures:
        if sig in data:
            return True  # UPX packed
```

#### **ELF (Linux) Signatures**

**Section Names:**
- `.upx0`
- `.upx1`

**Detection:**
```bash
readelf -S file.elf | grep upx
```

### UPX Packing Process

**Command:**
```bash
upx -9 --best --lzma original.exe -o packed.exe
```

**What Happens:**

1. **Read PE Headers**
   - Parse DOS header
   - Parse PE header
   - Parse section table

2. **Compress Sections**
   - Compress `.text` (code)
   - Compress `.data` (initialized data)
   - Compress `.rdata` (read-only data)

3. **Add Decompression Stub**
   - ~10-30 KB loader code
   - Includes LZMA decompressor
   - Entry point redirected to stub

4. **Reconstruct PE**
   - Create `UPX0` (empty, to be filled)
   - Create `UPX1` (compressed data)
   - Update PE headers
   - Write new file

**Size Comparison:**
```
Original:   500 KB
Packed:     225 KB (45% of original)
Stub Size:   25 KB
Net Savings: 250 KB
```

### UPX Unpacking Process

**Command:**
```bash
upx -d packed.exe -o unpacked.exe
```

**What Happens:**

1. **Detect UPX Signature**
   - Verify `UPX!` magic bytes
   - Check section names

2. **Read Compressed Data**
   - Locate `UPX1` section
   - Read compressed payload

3. **Decompress**
   - Apply LZMA decompression
   - Reconstruct original sections

4. **Rebuild PE**
   - Remove UPX sections
   - Restore original section table
   - Fix entry point to OEP
   - Write unpacked file

**Timeline:**
```
Detection:   < 0.1 seconds
Reading:     < 0.5 seconds
Decompression: 1-3 seconds (depends on size)
Rebuild:     < 0.5 seconds
Total:       2-5 seconds
```

---

## PE Overlay Technique

### What is an Overlay?

A **PE overlay** is data appended after the last PE section:

```
[DOS Header]
[PE Header]
[Section Table]
[.text Section]
[.data Section]
[.rsrc Section]
<--- END OF PE FILE (calculated)
[OVERLAY DATA]  ← Extra data here!
```

**File Size:**
```
Real File Size = PE_Calculated_Size + Overlay_Size
```

### Legitimate Uses

1. **Digital Signatures**
   - Authenticode signatures stored as overlay
   - PKCS#7 structure appended

2. **Installer Resources**
   - Setup.exe with compressed files attached
   - Self-extracting archives

3. **Game Resources**
   - Textures, sounds, models
   - DLC content

4. **Language Packs**
   - Localization data

### Malicious Uses

1. **Hidden Payloads**
   - Second-stage malware
   - Dropper executables

2. **Steganography**
   - Hide data in "legitimate" executable
   - Bypass content filters

3. **Nested Executables**
   - Dropper extracts overlay, executes
   - Multi-stage infections

4. **Anti-Analysis**
   - Confuse automated tools
   - Large overlays slow analysis

### Real-World Examples

#### **Stuxnet Worm (2010)**

Stuxnet used overlays to hide additional components:

```
File: stuxnet.sys (driver)
PE Size: 142 KB
Overlay Size: 378 KB (additional DLLs, exploits)
Total: 520 KB

Overlay Contents:
  - .stub (dropper code)
  - Additional drivers
  - PLC payload (Siemens controller attack code)
```

#### **APT Campaigns**

Many APT (Advanced Persistent Threat) groups use overlays:

```
File: invoice.pdf.exe
PE Size: 89 KB (fake PDF viewer)
Overlay Size: 2.3 MB (encrypted RAT)
Total: 2.39 MB

Detection: Standard AV scans only first 89 KB → Misses RAT
```

### PE Structure Deep Dive

**DOS Header (64 bytes):**
```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      // "MZ" signature (0x5A4D)
    ...
    DWORD e_lfanew;     // Offset to PE header (at 0x3C)
} IMAGE_DOS_HEADER;
```

**PE Header:**
```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                    // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;       // COFF header
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;
```

**COFF File Header:**
```c
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;              // Architecture (0x014C = x86)
    WORD  NumberOfSections;     // Number of sections
    DWORD TimeDateStamp;        // Compilation time
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader; // Usually 224 bytes
    WORD  Characteristics;      // Flags (executable, DLL, etc.)
} IMAGE_FILE_HEADER;
```

**Section Header (40 bytes each):**
```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];              // ".text", ".data", etc.
    DWORD VirtualSize;          // Size in memory
    DWORD VirtualAddress;       // RVA when loaded
    DWORD SizeOfRawData;        // Size on disk
    DWORD PointerToRawData;     // Offset in file
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;      // Flags (readable, writable, executable)
} IMAGE_SECTION_HEADER;
```

### Calculating PE Size

**Algorithm:**

```python
def calculate_pe_size(file_path):
    with open(file_path, 'rb') as f:
        # Read DOS header
        dos_header = f.read(64)
        pe_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]
        
        # Read PE signature
        f.seek(pe_offset)
        pe_sig = f.read(4)  # "PE\0\0"
        
        # Read COFF header
        coff_header = f.read(20)
        num_sections = struct.unpack('<H', coff_header[2:4])[0]
        size_of_optional_header = struct.unpack('<H', coff_header[16:18])[0]
        
        # Skip optional header
        f.seek(pe_offset + 24 + size_of_optional_header)
        
        # Read all section headers
        max_end = 0
        for i in range(num_sections):
            section = f.read(40)
            raw_size = struct.unpack('<I', section[16:20])[0]
            raw_address = struct.unpack('<I', section[20:24])[0]
            section_end = raw_address + raw_size
            if section_end > max_end:
                max_end = section_end
        
        return max_end  # True PE size
```

**Example:**

```
File: sample.exe
Total File Size: 1,048,576 bytes (1 MB)

Section Table:
  .text:  RawAddress=0x1000, RawSize=0x50000  → End=0x51000
  .data:  RawAddress=0x52000, RawSize=0x10000  → End=0x62000
  .rsrc:  RawAddress=0x63000, RawSize=0x20000  → End=0x83000

Calculated PE Size: 0x83000 (536,576 bytes)
Overlay Size: 1,048,576 - 536,576 = 512,000 bytes
Overlay Percentage: 48.8%
```

### Overlay Detection

**Command-Line Tool:**
```bash
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
overlay_offset = pe.get_overlay_data_start_offset()
if overlay_offset:
    print(f'Overlay detected at offset: {overlay_offset}')
"
```

**Using Module 12:**
```
Select: 4 (Strip Overlay)
→ Automatic detection and display
```

### Overlay Formats

Common formats found in overlays:

#### **1. ZIP Archives**
```
Magic: PK\x03\x04 (at overlay start)
Use: Installer packages, dropper payloads
```

#### **2. RAR Archives**
```
Magic: Rar!\x1a\x07 or Rar!\x1a\x07\x01\x00
Use: Compressed malware stages
```

#### **3. PDF Documents**
```
Magic: %PDF-1.x
Use: Decoy documents, exploits
```

#### **4. Image Files**
```
JPEG: \xff\xd8\xff\xe0 or \xff\xd8\xff\xe1
PNG:  \x89PNG\r\n\x1a\n
Use: Steganography, hiding data in images
```

#### **5. Nested PE Files**
```
Magic: MZ (0x5A4D)
Use: Multi-stage droppers, DLL payloads
```

### Overlay Analysis

**Entropy-Based Classification:**

```python
overlay_entropy = calculate_entropy(overlay_data)

if overlay_entropy >= 7.5:
    assessment = "Likely encrypted or compressed"
    threat = "HIGH - May contain hidden malware"
elif overlay_entropy >= 6.0:
    assessment = "Possibly compressed"
    threat = "MEDIUM - Investigate format"
else:
    assessment = "Plain data or structured format"
    threat = "LOW - Likely legitimate"
```

**Format Detection:**

```python
def detect_overlay_format(data):
    signatures = {
        b'PK\x03\x04': 'ZIP Archive',
        b'Rar!': 'RAR Archive',
        b'%PDF': 'PDF Document',
        b'\xff\xd8\xff': 'JPEG Image',
        b'\x89PNG': 'PNG Image',
        b'MZ': 'Nested PE Executable',
        b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
    }
    
    for magic, format_name in signatures.items():
        if data.startswith(magic):
            return format_name
    
    return 'Unknown Format'
```

---

## Module 12 Features

### 1. UPX Packing

**Workflow:**

1. Select file to pack
2. Choose compression level (1-9)
3. Execute UPX with optimal flags
4. Display size comparison

**Output:**
```
Original Size:  750 KB
Packed Size:    330 KB
Compression:    56.0%
Time:           2.3 seconds

UPX Options Used:
  - Compression Level: 9
  - Algorithm: LZMA (--best)
  - Options: --force
```

### 2. UPX Unpacking

**Workflow:**

1. Select packed file
2. Detect UPX signatures
3. Execute UPX decompression
4. Display expansion ratio

**Output:**
```
Packed Size:    330 KB
Unpacked Size:  750 KB
Expansion:      227%
Time:           1.8 seconds

UPX Signatures Detected:
  ✓ UPX! magic bytes
  ✓ UPX0 section
  ✓ UPX1 section
```

### 3. UPX Status Check

**Checks:**

- ✅ UPX installed (via PATH or common locations)
- ✅ UPX version (e.g., 4.0.2)
- ✅ UPX path (e.g., `/usr/bin/upx`)

**If Not Installed:**

Shows platform-specific installation instructions with commands.

### 4. Overlay Stripping

**Workflow:**

1. Select PE file
2. Calculate true PE size
3. Detect overlay
4. Display overlay info:
   - Size (bytes and %)
   - Entropy
   - Detected format
5. Confirm stripping
6. Create `.backup` file
7. Strip overlay, save clean PE

**Output:**
```
╔═══════════════════════════════════════╗
║       Overlay Information             ║
╚═══════════════════════════════════════╝

File:           malware.exe
Total Size:     1,048,576 bytes (1.00 MB)
PE Size:        536,576 bytes (0.51 MB)
Overlay Size:   512,000 bytes (0.49 MB)
Overlay %:      48.8%

Number of Sections: 3
  .text:  0x1000 - 0x51000 (320 KB)
  .data:  0x52000 - 0x62000 (64 KB)
  .rsrc:  0x63000 - 0x83000 (128 KB)

Overlay Analysis:
  Entropy: 7.85 / 8.00
  Format:  Unknown (possibly encrypted)
  Assessment: Likely encrypted or compressed

⚠️  This file has a suspicious overlay!

Proceed with stripping? (y/n): y

✓ Backup created: malware.exe.backup
✓ Overlay stripped successfully
✓ Clean PE saved: malware.exe (now 536,576 bytes)
```

### 5. Overlay Extraction

**Workflow:**

1. Select PE file with overlay
2. Extract overlay to `.overlay` file
3. Analyze extracted data

**Output:**
```
Extracting overlay from: sample.exe

Overlay Start:   0x83000 (536,576 bytes)
Overlay Size:    512,000 bytes
Output File:     sample.exe.overlay

✓ Overlay extracted successfully

You can now analyze: sample.exe.overlay
  - Check file type: file sample.exe.overlay
  - View hex: xxd sample.exe.overlay | head
  - Scan with AV: clamscan sample.exe.overlay
```

### 6. Overlay Analysis

**Detailed Analysis:**

```
═══ Overlay Analysis Results ═══

File:            dropper.exe
Total Size:      2,097,152 bytes (2.00 MB)
PE Size:         89,600 bytes (0.09 MB)
Overlay Size:    2,007,552 bytes (1.91 MB)
Overlay %:       95.7%

Overlay Characteristics:
  Start Offset:  0x15E00
  Entropy:       7.92 / 8.00
  Detected Format: ZIP Archive

Overlay Contents:
  ┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
  ┃ Property             ┃ Value         ┃
  ┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
  │ Magic Bytes          │ PK\x03\x04    │
  │ Format               │ ZIP Archive   │
  │ Entropy              │ 7.92          │
  │ Assessment           │ Compressed    │
  └──────────────────────┴───────────────┘

PE Section Table:
  ┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
  ┃ Section  ┃ Raw Address  ┃ Raw Size    ┃ Percentage ┃
  ┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
  │ .text    │ 0x1000       │ 40,960      │ 45.7%      │
  │ .data    │ 0xB000       │ 12,288      │ 13.7%      │
  │ .rsrc    │ 0xE000       │ 36,352      │ 40.6%      │
  └──────────┴──────────────┴─────────────┴────────────┘

Threat Assessment: 🔴 HIGH
Reason: Massive overlay (95.7%) containing ZIP archive
Recommendation: Extract and analyze ZIP contents
```

### 7. Installation Help

**Platform Detection:**

Automatically detects OS and shows relevant commands:

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install upx-ucl

# Fedora/RHEL
sudo dnf install upx

# Arch Linux
sudo pacman -S upx
```

**macOS:**
```bash
brew install upx
```

**Windows:**
```powershell
# Chocolatey
choco install upx

# Manual
1. Download: https://github.com/upx/upx/releases/latest
2. Extract to: C:\Program Files\upx\
3. Add to PATH environment variable
```

---

## Usage Examples

### Example 1: Pack Legitimate Tool

**Scenario:** Reduce size of portable security tool

```bash
$ python3 main.py
Select: 12 (Malware Packer/Unpacker)
Select: 1 (Pack Binary)

Select file: nmap.exe
Compression level (1-9, default 9): 9

[████████████████████] Packing... Done!

Original:  28,672,000 bytes (27.35 MB)
Packed:    8,912,384 bytes (8.50 MB)
Savings:   19,759,616 bytes (18.85 MB)
Ratio:     31.1% of original

✓ Packed file: nmap.exe (modified in-place)
✓ Backup created: nmap.exe.backup
```

### Example 2: Unpack Suspicious Malware

**Scenario:** Analyst received UPX-packed malware sample

```bash
$ python3 main.py
Select: 12 (Malware Packer/Unpacker)
Select: 2 (Unpack Binary)

Select file: trojan_sample.exe

Checking for UPX signatures...
✓ UPX! magic bytes found
✓ UPX0 section detected
✓ UPX1 section detected
→ File is UPX packed

[████████████████████] Unpacking... Done!

Packed:    145,408 bytes (142 KB)
Unpacked:  458,752 bytes (448 KB)
Expansion: 315.4%

✓ Unpacked file: trojan_sample.exe
✓ Original packed file: trojan_sample.exe.packed

Next steps:
  1. Scan with AV: clamscan trojan_sample.exe
  2. Analyze strings: strings trojan_sample.exe
  3. Check imports: pefile trojan_sample.exe
  4. Heuristic scan: Use Module 11 (Trojan Detection)
```

### Example 3: Analyze Dropper with Overlay

**Scenario:** Suspected dropper with large overlay

```bash
$ python3 main.py
Select: 12 (Malware Packer/Unpacker)
Select: 6 (Analyze Overlay)

Select file: suspected_dropper.exe

═══ Overlay Analysis ═══

Total File Size:    3,145,728 bytes (3.00 MB)
Calculated PE Size: 98,304 bytes (96 KB)
Overlay Size:       3,047,424 bytes (2.91 MB)
Overlay Percentage: 96.9%

⚠️  WARNING: Extremely large overlay!

Overlay Characteristics:
  Start Offset: 0x18000
  Entropy:      7.88 / 8.00
  Format:       Unknown (high entropy)
  Assessment:   Likely encrypted or compressed

Threat Level: 🔴 CRITICAL

Reasons for suspicion:
  - Overlay is 96.9% of file (extremely high)
  - High entropy (7.88) suggests encryption
  - Unknown format (no recognizable magic bytes)
  - Small PE stub (96 KB) is likely dropper

Recommendations:
  1. ISOLATE this file immediately
  2. Extract overlay: Option 5 (Extract Overlay)
  3. Analyze overlay entropy distribution
  4. Check PE stub for decryption routine
  5. Run in sandbox (Module 3) to observe behavior
  6. Search for decryption keys in PE stub strings
```

### Example 4: Clean Installer with Signature

**Scenario:** Legitimate installer with Authenticode signature

```bash
$ python3 main.py
Select: 12 (Malware Packer/Unpacker)
Select: 6 (Analyze Overlay)

Select file: setup_installer.exe

═══ Overlay Analysis ═══

Total File Size:    5,242,880 bytes (5.00 MB)
Calculated PE Size: 4,718,592 bytes (4.50 MB)
Overlay Size:       524,288 bytes (512 KB)
Overlay Percentage: 10.0%

Overlay Characteristics:
  Start Offset: 0x48000
  Entropy:      6.42 / 8.00
  Format:       PKCS#7 / Authenticode Signature
  Assessment:   Structured data (certificate)

Threat Level: 🟢 LOW

Analysis:
  - Moderate overlay size (10%) is normal for signed executables
  - Low-medium entropy (6.42) consistent with certificate data
  - PKCS#7 format indicates digital signature
  - Legitimate use case

Verification:
  ✓ Digital signature present
  ✓ Entropy in expected range
  ✓ Size proportional to main PE

Recommendation: Likely legitimate signed installer
```

---

## Advanced Techniques

### Manual Unpacking (OEP Finding)

**OEP (Original Entry Point):** Address where original code starts after unpacking.

**Manual Unpacking Steps:**

1. **Load in Debugger**
   ```
   x64dbg malware.exe
   ```

2. **Set Breakpoint on Common APIs**
   ```
   bp VirtualAlloc      # Memory allocation
   bp VirtualProtect    # Change memory permissions
   bp WriteProcessMemory # Process injection
   ```

3. **Run Until Unpacking**
   - Step through decompression stub
   - Watch for large memory writes

4. **Find OEP**
   ```
   Look for:
   - PUSH/CALL/RETN sequences
   - Jump to newly allocated memory
   - PE header reconstruction
   ```

5. **Dump Unpacked Code**
   ```
   Scylla: Dump process → Rebuild imports → Fix OEP
   ```

### Custom Packer Detection

**Indicators:**

```python
def detect_custom_packer(file_path):
    indicators = []
    
    pe = pefile.PE(file_path)
    
    # High entropy in code section
    text_section = pe.sections[0]
    if calculate_entropy(text_section.get_data()) > 7.5:
        indicators.append("High entropy in .text section")
    
    # Few imports (dynamic loading)
    if len(pe.DIRECTORY_ENTRY_IMPORT) < 5:
        indicators.append("Very few imports (< 5)")
    
    # Suspicious section names
    suspicious = ['.packed', '.enigma', '.aspack', '.petite']
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name.lower() in suspicious:
            indicators.append(f"Suspicious section: {name}")
    
    # Large raw/virtual size discrepancy
    for section in pe.sections:
        if section.Misc_VirtualSize > section.SizeOfRawData * 10:
            indicators.append("Large virtual/raw size discrepancy")
    
    return indicators
```

### Overlay-Based Dropper Analysis

**Step 1: Extract Overlay**
```bash
python3 main.py → 12 → 5 (Extract Overlay)
```

**Step 2: Identify Format**
```bash
file dropper.exe.overlay
# Output: "dropper.exe.overlay: gzip compressed data"
```

**Step 3: Decompress**
```bash
mv dropper.exe.overlay dropper.gz
gunzip dropper.gz
```

**Step 4: Analyze Extracted Payload**
```bash
file dropper
# Output: "dropper: PE32 executable (GUI) Intel 80386"

# Now analyze the nested PE
python3 main.py → 11 (Trojan Detection)
```

---

## Anti-Analysis Techniques

### Techniques Used by Malware

1. **Multi-Layer Packing**
   ```
   [Original] → UPX → ASPack → Themida
   Requires multiple unpacking stages
   ```

2. **VM-Based Obfuscation**
   ```
   Code virtualized into custom instruction set
   Interpreter executes at runtime
   Examples: VMProtect, Code Virtualizer
   ```

3. **Metamorphic Engine**
   ```
   Code changes structure with each execution
   Same functionality, different assembly
   Example: Win32/Simile virus
   ```

4. **Anti-Dump**
   ```c
   // Overwrite PE header after loading
   PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)base;
   memset(pDos, 0, 4096);  // Erase headers
   ```

5. **Stolen Bytes**
   ```
   Packer modifies original entry point
   Executes stolen instructions in stub
   Jump back after unpacking
   Prevents static reconstruction
   ```

### Countermeasures

1. **Automated Unpacking** (Generic Unpacker)
   - Let malware unpack itself in sandbox
   - Dump memory after execution
   - Tools: PE-sieve, Hollows Hunter

2. **Emulation** (Dynamic Analysis)
   - Execute in emulator (QEMU, Unicorn)
   - Trace all instructions
   - Capture unpacked code

3. **Memory Forensics**
   - Dump running process memory
   - Scan for PE headers (MZ/PE)
   - Extract executables from memory

4. **Instrumentation**
   - DynamoRIO / Pin / Frida
   - Trace execution flow
   - Hook unpacking APIs

---

## Integration with Other Modules

### Module 11: Trojan Detection

**Workflow:**
```
1. Unpack with Module 12 (if UPX detected)
2. Scan unpacked binary with Module 11
3. Higher accuracy (no packing obfuscation)
```

### Module 3: Dynamic Sandbox

**Workflow:**
```
1. Analyze overlay with Module 12
2. Extract suspicious overlay
3. Run in Module 3 sandbox
4. Monitor unpacking behavior
```

### Module 4: Signature Generator

**Workflow:**
```
1. Unpack multiple variants
2. Find common bytes across unpacked samples
3. Generate YARA rule for unpacked code
4. Ignore packer polymorphism
```

---

## Limitations

### What This Module Cannot Do

1. **Complex Custom Packers**: Only handles UPX (most common)
2. **VM Protectors**: VMProtect, Themida require specialized tools
3. **Multi-Stage Unpacking**: Only unpacks one layer
4. **Anti-Debugging**: Malware may detect analysis environment
5. **Memory-Only Packers**: Cannot unpack fileless malware

### Known Limitations

- **UPX Variants**: Some malware modifies UPX signatures
- **Corrupted PE**: Invalid PE headers break overlay detection
- **Large Files**: >100 MB files may be slow
- **Packed Overlays**: Overlay itself may be packed

---

## Best Practices

### For Malware Analysts

1. **Always Backup**: Module creates `.backup` files automatically
2. **Unpack Before Analysis**: Run Module 12 → then Module 11
3. **Check Entropy**: High entropy → likely packed
4. **Verify Signatures**: UPX detection can have false positives
5. **Sandbox First**: Unpack in isolated environment

### For Incident Responders

1. **Triage**: Quick UPX check on suspicious executables
2. **IOC Extraction**: Unpack → strings → extract C2 addresses
3. **Signature Generation**: Unpack → generate rules for unpacked code
4. **Timeline Analysis**: Overlay timestamps may reveal packing time

### For Security Researchers

1. **Variant Analysis**: Unpack multiple samples, compare
2. **Packer Fingerprinting**: Document custom packer signatures
3. **Automated Pipelines**: Script Module 12 for batch processing
4. **Evasion Testing**: Pack your tools, test EDR detection

---

## Conclusion

The Malware Packer/Unpacker module provides essential capabilities for analyzing obfuscated malware. By combining UPX handling with PE overlay analysis, it addresses the two most common packing techniques used by modern malware. Understanding these techniques is fundamental to malware analysis, as packed samples cannot be effectively analyzed without first unpacking them.

**Key Takeaways:**

- **80% of malware uses packing** → Unpacking is essential
- **UPX is most common** → Learn its signatures
- **Overlays hide payloads** → Always check file size vs PE size
- **Entropy reveals packing** → H > 7.5 is suspicious
- **Unpack before analysis** → Static analysis requires unpacked code

**Remember:** Packing is not inherently malicious, but most malware uses it. Always combine unpacking with other analysis modules for comprehensive assessment.

---

## References

### Tools

- **UPX Official**: https://upx.github.io/
- **PEiD**: Packer identifier (legacy but useful)
- **Detect It Easy (DIE)**: Modern packer detection
- **PE-bear**: PE editor with overlay support

### Papers

1. **Ugarte-Pedrero et al. (2015)**: "On the Adoption of Anomalous Entropy for the Detection of Packed Malware"
2. **Perdisci et al. (2008)**: "Classification of Packed Executables for Accurate Computer Virus Detection"
3. **Royal et al. (2006)**: "PolyUnpack: Automating the Hidden-Code Extraction of Unpack-Executing Malware"

### Resources

- **SANS Reverse Engineering Malware (FOR610)**
- **Practical Malware Analysis** (Book by Sikorski & Honig)
- **Malware Unicorn**: https://malwareunicorn.org/

---

**Module Status:** ✅ Production Ready  
**Last Updated:** January 2026  
**Version:** 1.0 FINAL
