# Module 4: Behavioral Signature Generator

## Overview

The Behavioral Signature Generator automatically creates YARA rules from binary files by extracting characteristic features such as strings, opcodes, and metadata. This module enables rapid detection rule creation for malware analysis and threat hunting.

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Status**: Production Ready ✅

---

## Features

- **Automatic String Extraction**: ASCII and Unicode string detection
- **Opcode Extraction**: Entry point byte signature capture
- **Smart Filtering**: Removes common garbage and generic strings
- **YARA Rule Generation**: Standards-compliant YARA output
- **Syntax Highlighting**: Beautiful code display with Rich
- **File Export**: Saves rules to `detected.yar`

---

## Technical Details

### Components

#### 1. yara_builder.py (YaraBuilder Class)

**Purpose**: Core rule generation engine

**Key Methods**:

- `extract_strings(min_length=4, max_strings=20)`:
  - Extracts ASCII strings using regex: `[\x20-\x7e]{4,}`
  - Extracts Unicode (UTF-16LE) strings
  - Filters invalid/garbage strings
  - Returns up to 20 unique strings

- `extract_opcodes(num_bytes=20)`:
  - Locates PE entry point if available
  - Extracts first N bytes as hex signature
  - Returns space-separated hex string

- `build_rule(rule_name=None)`:
  - Generates complete YARA rule
  - Includes meta section with author/date/hash
  - Adds strings section with opcodes + extracted strings
  - Creates condition with logical OR

- `save_rule(output_path)`:
  - Writes rule to file

#### 2. main.py (User Interface)

**Purpose**: Interactive module interface

**Workflow**:
1. Display module banner
2. Prompt for target binary
3. Optional: Get custom rule name
4. Extract strings and opcodes
5. Display extracted data in tables
6. Generate and display YARA rule with syntax highlighting
7. Save to `data/detected.yar`
8. Show usage instructions

---

## Algorithm Logic

### String Extraction

```
1. Read binary data
   ↓
2. Search for ASCII patterns: [\x20-\x7e]{4,}
   ↓
3. Search for Unicode patterns: (?:[\x20-\x7e]\x00){4,}
   ↓
4. Filter strings:
   - Remove all-same-character strings
   - Remove < 40% alphanumeric
   - Remove common system strings
   ↓
5. Deduplicate and sort by length
   ↓
6. Return top 20 strings
```

### Opcode Extraction

```
1. Check for MZ header (PE signature)
   ↓
2. If PE file:
   - Read e_lfanew (offset 0x3c)
   - Check PE\x00\x00 signature
   - Read AddressOfEntryPoint (PE+0x28)
   - Use entry point as offset
   ↓
3. Extract N bytes from offset
   ↓
4. Convert to hex string (space-separated)
```

### YARA Rule Structure

```yara
rule <name>
{
    meta:
        description = "Auto-generated YARA rule for <filename>"
        author = "MalSpectra - Sai Srujan Murthy"
        date = "YYYY-MM-DD"
        hash = "Generated from <filename>"
    
    strings:
        $opcode = { <hex bytes> }
        $str1 = "<string1>" ascii wide
        $str2 = "<string2>" ascii wide
        ...
    
    condition:
        $opcode or
        N of ($str*)
}
```

---

## Usage

### Basic Usage

```bash
# From main menu
python3 main.py
# Select option 4
# Enter binary path
# Enter rule name (optional)
# View generated rule
```

### Example Session

```
Target: /usr/bin/ssh
Rule name: ssh_detect

═══ EXTRACTED DATA ═══

Strings Found: 15
┏━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ # ┃ String              ┃ Length┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ 1 │ OpenSSH             │ 7     │
│ 2 │ ssh-keygen          │ 10    │
│ 3 │ authorized_keys     │ 15    │
└───┴─────────────────────┴───────┘

Opcodes (Entry Point):
48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18

═══ GENERATED YARA RULE ═══

rule ssh_detect
{
    meta:
        description = "Auto-generated YARA rule for ssh"
        author = "MalSpectra - Sai Srujan Murthy"
        date = "2026-01-03"
    
    strings:
        $opcode = { 48 89 5c 24 08 48 89 6c 24 10 }
        $str1 = "authorized_keys" ascii wide
        $str2 = "ssh-keygen" ascii wide
        $str3 = "OpenSSH" ascii wide
    
    condition:
        $opcode or
        3 of ($str*)
}

✓ YARA rule saved to: data/detected.yar
```

---

## YARA Rule Usage

### Scanning Files

```bash
# Scan single file
yara data/detected.yar /path/to/suspicious/file

# Scan directory recursively
yara -r data/detected.yar /path/to/directory/

# Verbose output
yara -s data/detected.yar /path/to/file
```

### Integration with Tools

```bash
# With malware analysis tools
clamav-scan -d data/detected.yar /scan/path/

# With Yara-Python
python3 << EOF
import yara
rules = yara.compile(filepath='data/detected.yar')
matches = rules.match('/path/to/file')
print(matches)
EOF
```

---

## String Filtering Logic

### Valid String Criteria

A string is considered valid if:
1. **Length ≥ 4 characters**
2. **Character diversity**: At least 2 unique characters
3. **Alphanumeric ratio ≥ 40%**
4. **Not in common garbage list**:
   - DOS stub messages
   - Generic Windows API names
   - Common compiler artifacts

### Example Filtering

```
Input: "AAAAAAA"              → Rejected (no diversity)
Input: "!@#$%^&"              → Rejected (low alphanum)
Input: "LoadLibrary"          → Rejected (common API)
Input: "MyMalwareString123"   → Accepted ✓
```

---

## Use Cases

### 1. Malware Family Detection
Generate rules from known malware samples to detect variants.

### 2. Threat Hunting
Create IOC-based rules for proactive scanning.

### 3. Reverse Engineering
Quickly identify similar binaries based on string/opcode patterns.

### 4. Incident Response
Generate detection rules from artifacts found during investigation.

### 5. Automated Analysis
Integrate into malware analysis pipelines for automatic rule generation.

---

## Limitations

### Technical Limitations
- **PE-focused**: Entry point detection optimized for PE files
- **Static analysis only**: No runtime behavior analysis
- **String limitations**: May miss encrypted/obfuscated strings
- **False positives**: Generic strings may match benign files

### YARA Limitations
- Generated rules may need manual refinement
- Condition logic is basic (can be enhanced)
- No support for advanced YARA features (imports, regex, etc.)

---

## Advanced Customization

### Adjust String Count

```python
# In main.py or direct usage
builder = YaraBuilder('binary.exe')
builder.extract_strings(min_length=6, max_strings=30)
```

### Custom Opcode Length

```python
builder.extract_opcodes(num_bytes=50)  # Extract 50 bytes
```

### Manual Rule Editing

After generation, edit `data/detected.yar`:
- Add more specific conditions
- Include file size checks
- Add regex patterns
- Use YARA modules (pe, elf, math)

### Example Enhanced Rule

```yara
import "pe"

rule enhanced_malware_detect
{
    meta:
        description = "Enhanced detection rule"
        author = "MalSpectra - Sai Srujan Murthy"
    
    strings:
        $opcode = { 48 89 5c 24 08 }
        $str1 = "malicious" ascii
        $str2 = "payload" ascii
    
    condition:
        pe.is_pe and
        pe.number_of_sections > 3 and
        filesize < 1MB and
        ($opcode or all of ($str*))
}
```

---

## Best Practices

### 1. Rule Naming
- Use descriptive names: `ransomware_wannacry_v2`
- Avoid spaces and special characters
- Follow snake_case convention

### 2. String Selection
- Choose unique, characteristic strings
- Avoid overly common strings
- Look for error messages, C&C domains, file paths

### 3. Opcode Signatures
- Entry point opcodes are distinctive
- Compare similar malware samples
- Avoid generic compiler stubs

### 4. Testing Rules
```bash
# Test against known good files first
yara detected.yar /bin/* | wc -l  # Should be low

# Test against known bad files
yara detected.yar /malware/samples/ | wc -l  # Should match
```

### 5. Rule Management
- Version control your rules (git)
- Document rule purpose and targets
- Regularly update and refine
- Test for false positives

---

## Troubleshooting

### "No strings extracted"
**Cause**: Binary has very few readable strings (packed/encrypted)  
**Solution**: Use unpacking tools first, or focus on opcode signatures

### "Rule matches everything"
**Cause**: Strings too generic  
**Solution**: Manually edit rule, add more specific conditions

### "Invalid YARA syntax"
**Cause**: Special characters in strings not properly escaped  
**Solution**: Check generated rule, fix escape sequences

### "File not found"
**Cause**: Invalid binary path  
**Solution**: Use absolute paths or verify file exists

---

## References

- **YARA Documentation**: https://yara.readthedocs.io/
- **YARA Rules Repository**: https://github.com/Yara-Rules/rules
- **PE Format**: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- **String Extraction**: https://github.com/fireeye/flare-floss

---

## Example Output

### Generated Rule File

**File**: `data/detected.yar`

```yara
rule test_malware_safe
{
    meta:
        description = "Auto-generated YARA rule for test_malware_safe.py"
        author = "MalSpectra - Sai Srujan Murthy"
        date = "2026-01-03"
        hash = "Generated from test_malware_safe.py"
    
    strings:
        $opcode = { 23 21 2f 75 73 72 2f 62 69 6e 2f 65 6e 76 20 70 79 74 68 6f 6e }
        $str1 = "MalSpectra" ascii wide
        $str2 = "Test content from safe malware simulation" ascii wide
        $str3 = "malware_payload.dat" ascii wide
        $str4 = "infected.txt" ascii wide
    
    condition:
        $opcode or
        4 of ($str*)
}
```

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Behavioral Signature Generator  
**Version**: 1.0
