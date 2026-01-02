# Module 9: Ransomware Decryption Helper

## Overview

The Ransomware Decryption Helper is a comprehensive tool for identifying ransomware families and providing guidance toward legitimate decryption resources. It uses file extension analysis and entropy calculation to determine if a file has been encrypted by ransomware, then directs users to appropriate decryption tools and resources.

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Status**: Production Ready 🔐 Educational Tool

---

## ⚠️ IMPORTANT DISCLAIMERS

### This Tool Does NOT

- ❌ Decrypt files directly
- ❌ Remove ransomware from systems
- ❌ Guarantee recovery
- ❌ Endorse paying ransoms

### This Tool DOES

- ✓ Identify ransomware families by extension
- ✓ Verify encryption via entropy analysis
- ✓ Provide links to legitimate decryption resources
- ✓ Offer prevention recommendations
- ✓ Educate about ransomware threats

**NEVER PAY THE RANSOM** - It funds criminal operations and doesn't guarantee file recovery.

---

## Features

- **Family Identification**: Recognizes 14 major ransomware families
- **Entropy Analysis**: Validates encryption using Shannon entropy
- **Resource Links**: Direct links to NoMoreRansom.org and decryption tools
- **Confidence Levels**: HIGH/MEDIUM/LOW identification confidence
- **Rich Reporting**: Detailed analysis with visual entropy bars
- **Prevention Tips**: Security recommendations to avoid future infections

---

## Technical Details

### Components

#### 1. identifier.py (RansomwareIdentifier Class)

**Purpose**: Core identification and entropy calculation engine

**Key Methods**:

- `identify_family(filename)`: Identify ransomware by extension
- `calculate_entropy(file_path)`: Compute Shannon entropy
- `verify_encryption(file_path)`: Confirm encryption status
- `analyze_file(file_path)`: Complete analysis workflow

**Supported Families**: 14 major families including WannaCry, Locky, Cerber, REvil, Ryuk, Maze, and more.

#### 2. main.py (User Interface)

**Purpose**: Interactive ransomware analysis interface

**Features**:
- File selection with automatic detection
- Entropy visualization with progress bars
- Color-coded threat levels
- Comprehensive resource links
- Prevention education

---

## Detection Techniques

### 1. Extension-Based Identification

**Known Ransomware Extensions**:

| Extension | Family | Year | Severity | Notes |
|-----------|--------|------|----------|-------|
| `.wannacry` | WannaCry | 2017 | CRITICAL | EternalBlue exploit |
| `.locky` | Locky | 2016 | HIGH | Email-based |
| `.cerber` | Cerber | 2016 | HIGH | RaaS model |
| `.cryptolocker` | CryptoLocker | 2013 | CRITICAL | First major campaign |
| `.crypto` | TeslaCrypt | 2015 | HIGH | ✓ Decryptor available |
| `.petya` | Petya/NotPetya | 2017 | CRITICAL | Disk encryption |
| `.ryuk` | Ryuk | 2018 | CRITICAL | Targeted attacks |
| `.maze` | Maze | 2019 | CRITICAL | Double extortion |
| `.revil` | REvil/Sodinokibi | 2019 | CRITICAL | RaaS |
| `.dharma` | Dharma/Crysis | 2016 | HIGH | Organizational targets |
| `.phobos` | Phobos | 2019 | HIGH | Dharma variant |

**Detection Logic**:

```python
def identify_family(filename):
    extension = Path(filename).suffix.lower()
    
    # Direct match
    if extension in RANSOMWARE_EXTENSIONS:
        return RANSOMWARE_EXTENSIONS[extension]
    
    # Double extension check (file.txt.locky)
    if len(suffixes) >= 2:
        double_ext = ''.join(suffixes[-2:])
        if matches(double_ext):
            return family_info
    
    # Partial match
    for known_ext in RANSOMWARE_EXTENSIONS:
        if known_ext in extension:
            return partial_match
    
    return None
```

---

### 2. Entropy-Based Verification

**What is Entropy?**

**Shannon entropy** measures the randomness/disorder in data. Encrypted data has high entropy because it appears random.

**Formula**:

```
H(X) = -Σ P(x) × log₂(P(x))

Where:
- H(X) = Entropy (0 to 8 for bytes)
- P(x) = Probability of byte value x
- Σ = Sum over all possible byte values (0-255)
```

**Entropy Scale**:

```
0.0 - 2.0  │ Highly structured (source code, text)
2.0 - 4.0  │ Moderate structure (executables)
4.0 - 6.0  │ Mixed content (multimedia)
6.0 - 7.0  │ Compressed data
7.0 - 7.5  │ High compression / weak encryption
7.5 - 8.0  │ Strong encryption / random data  ← RANSOMWARE
```

**Implementation**:

```python
from collections import Counter
import math

def calculate_entropy(file_path, sample_size=102400):  # 100KB sample
    with open(file_path, 'rb') as f:
        data = f.read(sample_size)
    
    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy
```

**Threshold**:

```python
ENTROPY_THRESHOLD = 7.5

if entropy >= 7.5:
    assessment = "HIGH - File is likely encrypted or compressed"
    is_encrypted = True
```

**Why 7.5?**

- Normal files: 4.0-6.5
- Compressed files: 6.5-7.5
- Encrypted files: 7.5-8.0
- Perfectly random: 8.0

---

## Usage

### Prerequisites

```bash
# No external dependencies required
# Uses Python standard library only

python3 main.py
```

### Basic Workflow

```bash
# 1. Start MalSpectra
python3 main.py

# 2. Select Module 9 (Ransomware Helper)

# 3. Enter encrypted file path

# 4. Review identification and entropy results

# 5. Follow decryption resource links
```

### Example Session

```
═══ RANSOMWARE DECRYPTION HELPER ═══
Family Identification & Decryption Resources

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com

╔═══════════════════════════════════════╗
║        ⚠ IMPORTANT NOTES ⚠            ║
╠═══════════════════════════════════════╣
║ • This tool identifies ransomware     ║
║   families                            ║
║ • It does NOT decrypt files directly  ║
║ • Provides links to legitimate tools  ║
║ • Always backup before decryption     ║
║ • Never pay the ransom                ║
╚═══════════════════════════════════════╝

Select Encrypted File

Suspicious files found in data/:
  [1] document.txt.locky (15.23 KB)
  [2] photo.jpg.wannacry (234.56 KB)

Enter encrypted file path: data/document.txt.locky

✓ Selected file: data/document.txt.locky

Initializing ransomware identifier...
✓ Identifier ready

⠋ Analyzing file...
✓ Analysis complete

══════════════════════════════════════════════════════════════════

File Information:

┌─────────────┬──────────────────────────────────────┐
│ File Name   │ document.txt.locky                   │
│ File Size   │ 15.23 KB                             │
│ Extension   │ .locky                               │
│ Full Path   │ /home/user/data/document.txt.locky   │
└─────────────┴──────────────────────────────────────┘

Ransomware Family Identification:

✓ IDENTIFIED - Confidence: HIGH

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Attribute       ┃ Details                                ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Family Name     │ Locky                                  │
│ Extension       │ .locky                                 │
│ Also Known As   │ Locky Ransomware                       │
│ First Seen      │ 2016                                   │
│ Severity        │ HIGH                                   │
│ Description     │ Distributed via malicious email        │
│                 │ attachments                            │
└─────────────────┴────────────────────────────────────────┘

Encryption Verification:

Shannon Entropy: 7.9654 / 8.0000
████████████████████████████████████████  (7.97/8.00)
Threshold: 7.5

✗ ENCRYPTED - HIGH - File is likely encrypted or compressed

══════════════════════════════════════════════════════════════════

Recommended Actions:

✓ Family Identified - Seek Decryptor

1. Visit NoMoreRansom.org:
   https://www.nomoreransom.org/en/decryption-tools.html

2. Search for decryptor:
   Search for: "Locky decryptor"

3. Backup encrypted files:
   Make copies before attempting decryption

4. Report to authorities:
   Consider reporting to law enforcement

Useful Resources:

  • NoMoreRansom.org: https://www.nomoreransom.org/
  • ID Ransomware: https://id-ransomware.malwarehunterteam.com/
  • Emsisoft Decryptors: https://www.emsisoft.com/ransomware-decryption-tools/
  • Kaspersky Tools: https://www.kaspersky.com/downloads/thank-you/free-ransomware-decryptors
  • Avast Decryptors: https://www.avast.com/ransomware-decryption-tools

Prevention Tips (For Future):

  ✓ Regular backups (3-2-1 rule)
  ✓ Keep software updated
  ✓ Use antivirus/anti-malware
  ✓ Be cautious with email attachments
  ✓ Enable email filtering
  ✓ Restrict user permissions
  ✓ Disable macros by default
  ✓ Network segmentation
  ✓ Employee security training
```

---

## Use Cases

### 1. Incident Response
Quickly identify ransomware family during active incident.

### 2. Forensic Analysis
Determine which ransomware strain infected a system.

### 3. Decryption Planning
Find appropriate decryption tools for specific families.

### 4. Victim Support
Guide ransomware victims toward legitimate recovery resources.

### 5. Security Training
Educate users about ransomware identification and response.

---

## Entropy Analysis in Depth

### Entropy by File Type

| File Type | Typical Entropy | Example |
|-----------|-----------------|---------|
| Plain Text | 3.5 - 5.5 | Source code, documents |
| Executables | 5.0 - 6.5 | .exe, .dll, .so |
| Images (uncompressed) | 6.0 - 7.0 | .bmp, .raw |
| Compressed | 7.0 - 7.8 | .zip, .gz, .jpg |
| **Encrypted** | **7.8 - 8.0** | **Ransomware** |

### Visual Entropy Comparison

```
Plain Text File (entropy: 4.2)
████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░

JPEG Image (entropy: 7.1)
████████████████████████████████░░░░░░░░

Encrypted File (entropy: 7.95)
████████████████████████████████████████
```

### Sample Sizes

```python
# Small files (< 100KB): Read entire file
sample_size = file_size

# Large files: Sample first 100KB
sample_size = min(102400, file_size)
```

**Why 100KB sample?**
- Sufficient for statistical accuracy
- Fast calculation
- Represents file characteristics well

---

## Decryption Resources

### NoMoreRansom.org

**Official Project** by Europol, Dutch Police, Kaspersky, McAfee

- 120+ free decryption tools
- Supports 150+ ransomware families
- Multiple languages
- Verified and safe

### ID Ransomware

**Free Service** by Michael Gillespie

- Upload ransom note or encrypted file
- Automatic family identification
- Decryption tool recommendations
- Community-driven database

### Vendor Tools

**Emsisoft Decryption Tools**:
- TeslaCrypt, Damage, Xorist, Apocalypse
- CryptoDefense, Stampado, and more

**Kaspersky Decryptors**:
- Shade, Rakhni, Rannoh, CoinVault
- Wildfire, Crysis, and others

**Avast Decryptors**:
- AES_NL, Alcatraz, Apocalypse
- BadBlock, Bart, CrySiS

---

## Known Limitations

### False Positives

**Compressed Files** may show high entropy:
- ZIP, RAR, 7z archives
- JPEG, PNG images (already compressed)
- MP3, MP4 media files

**Workaround**: Check file extension and context

### False Negatives

**Partial Encryption**:
- Some ransomware only encrypts file headers
- Low entropy overall but file still locked

**Custom Ransomware**:
- Unknown families with custom extensions
- Not in database

### No Actual Decryption

- Tool identifies, doesn't decrypt
- Must use external decryption tools
- Success depends on decryptor availability

---

## Advanced Features

### Custom Extension Database

Add new ransomware families:

```python
RANSOMWARE_EXTENSIONS['.newmalware'] = {
    'family': 'NewMalware',
    'aka': ['NewMalware Ransomware'],
    'year': '2025',
    'severity': 'HIGH',
    'description': 'Description here',
    'nomoreransom': 'https://www.nomoreransom.org/',
    'decryptor_available': False
}
```

### Batch Analysis

Analyze multiple files:

```python
import os
from pathlib import Path

identifier = RansomwareIdentifier()

for file in Path('/encrypted').glob('*'):
    if file.is_file():
        results = identifier.analyze_file(str(file))
        print(f"{file.name}: {results['family_identification']['family']}")
```

### Entropy Histogram

Visualize byte distribution:

```python
from collections import Counter
import matplotlib.pyplot as plt

with open(file_path, 'rb') as f:
    data = f.read(102400)

byte_counts = Counter(data)
plt.bar(byte_counts.keys(), byte_counts.values())
plt.xlabel('Byte Value (0-255)')
plt.ylabel('Frequency')
plt.title('Byte Distribution')
plt.show()
```

---

## Best Practices

### 1. Never Pay Ransom
- Funds criminal activity
- No guarantee of decryption
- May mark you as willing to pay

### 2. Backup Immediately
- Copy encrypted files before attempting decryption
- Store in separate location
- Protect backups from overwriting

### 3. Document Everything
- Screenshot ransom notes
- Save file samples
- Record extension changes
- Log timeline of infection

### 4. Report to Authorities
- Local police cyber crime unit
- FBI IC3 (Internet Crime Complaint Center)
- National cyber security center
- Helps track and prosecute attackers

### 5. Use Legitimate Tools Only
- Verify tool sources
- Use NoMoreRansom.org
- Avoid "pay to decrypt" services
- Be wary of scams

### 6. Prevention is Key
- **3-2-1 Backup Rule**: 3 copies, 2 different media, 1 offsite
- Regular patching and updates
- Email attachment filtering
- User security awareness training
- Network segmentation

---

## Troubleshooting

### "Could not identify ransomware family"

**Possible Reasons**:
- Unknown or new ransomware variant
- Custom targeted ransomware
- Extension was manually changed
- Not actually ransomware

**Solution**: Use ID Ransomware service with ransom note

### "File appears encrypted but entropy is low"

**Possible Reasons**:
- Partial encryption (headers only)
- Weak encryption algorithm
- Corrupted file

**Solution**: Try decryption tools anyway, check file structure

### "Identified family but no decryptor available"

**Reality**: Many families don't have decryptors yet  
**Options**:
- Keep files backed up
- Monitor NoMoreRansom.org for new tools
- Restore from clean backups if available

---

## References

- **NoMoreRansom.org**: https://www.nomoreransom.org/
- **ID Ransomware**: https://id-ransomware.malwarehunterteam.com/
- **Shannon Entropy**: https://en.wikipedia.org/wiki/Entropy_(information_theory)
- **Ransomware Report**: https://www.coveware.com/blog/ransomware-trends
- **CISA Ransomware Guide**: https://www.cisa.gov/stopransomware

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Ransomware Decryption Helper  
**Version**: 1.0  
**Status**: 🔐 Production Ready - Educational Tool
