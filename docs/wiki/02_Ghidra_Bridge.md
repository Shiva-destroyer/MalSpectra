# Module 2: Ghidra Bridge

## Overview

The Ghidra Bridge module provides automated integration with the Ghidra headless analyzer, allowing you to perform binary analysis without opening the Ghidra GUI. This module generates Python scripts dynamically, executes them through Ghidra's headless mode, and presents the results in a clean, formatted table.

## Features

- **Headless Ghidra Integration**: Runs Ghidra analysis without GUI
- **Configuration Management**: Persistent storage of Ghidra path
- **Dynamic Script Generation**: Creates analysis scripts on-the-fly
- **Function Analysis**: Extracts function information (name, address, size, parameters, callers)
- **String Extraction**: Finds and exports all strings from binaries
- **JSON Output**: Structured results for easy parsing

## Technical Details

### Components

1. **config_manager.py**
   - Manages Ghidra headless analyzer path
   - Stores configuration in JSON format
   - Validates paths before saving

2. **script_gen.py**
   - Generates Ghidra Python scripts dynamically
   - Supports function analysis and string extraction
   - Uses Ghidra API internally

3. **bridge.py**
   - Executes Ghidra headless analyzer via subprocess
   - Builds command: `analyzeHeadless <project> -import <file> -postScript <script>`
   - Handles timeouts and error conditions
   - Parses JSON output from Ghidra scripts

4. **main.py**
   - User interface for module
   - Configuration workflow
   - Result display with Rich tables

### Ghidra Headless Command

```bash
analyzeHeadless /tmp/ghidra_project temp_project \
    -import /path/to/binary \
    -postScript /path/to/script.py \
    -deleteProject
```

**Parameters:**
- `/tmp/ghidra_project`: Temporary project directory
- `temp_project`: Project name
- `-import`: Binary file to analyze
- `-postScript`: Python script to run after analysis
- `-deleteProject`: Clean up after analysis

### Function Analysis Script

The generated script uses Ghidra's API to:
1. Get function manager: `currentProgram.getFunctionManager()`
2. Iterate through all functions
3. Extract function details:
   - Name and entry point address
   - Function body size
   - Parameter count
   - External function flag
   - Calling functions (callers)
4. Export to JSON format

### Configuration Storage

Configuration is stored in `core/ghidra_config.json`:
```json
{
    "ghidra_headless_path": "/path/to/ghidraRun"
}
```

## Usage

### Initial Setup

1. **Select Module 2** from main menu
2. **Configure Ghidra** (first-time only):
   - Choose "Configure Ghidra Path"
   - Enter path to `analyzeHeadless` script
   - Common locations:
     - Linux: `/opt/ghidra/support/analyzeHeadless`
     - macOS: `/Applications/ghidra/support/analyzeHeadless`
     - Windows: `C:\ghidra\support\analyzeHeadless.bat`

### Running Analysis

1. **Select Module 2** from main menu
2. **Choose "Run Analysis"**
3. **Enter target binary path**
4. **Select analysis type**:
   - Function Analysis
   - String Extraction
5. **View results** in formatted table

### Function Analysis Output

The function analysis displays:
- **Function**: Function name
- **Address**: Entry point address (hex)
- **Size**: Function body size in bytes
- **Params**: Number of parameters
- **External**: Whether function is external
- **Called By**: Number of calling functions

### Example Output

```
═══════════════════════════════════════════════════════════════
                     GHIDRA FUNCTION ANALYSIS
═══════════════════════════════════════════════════════════════
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┓
┃ Function     ┃ Address    ┃ Size ┃ Params ┃ External ┃ Called By┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━┩
│ main         │ 0x00401000 │ 256  │ 2      │ No       │ 1        │
│ sub_401100   │ 0x00401100 │ 128  │ 1      │ No       │ 3        │
│ printf       │ 0x00402000 │ 0    │ 0      │ Yes      │ 5        │
└──────────────┴────────────┴──────┴────────┴──────────┴──────────┘
```

## Algorithmic Logic

### Analysis Workflow

```
1. User selects "Run Analysis"
   ↓
2. Check if Ghidra is configured
   - If NO → Prompt for path
   - If YES → Continue
   ↓
3. Get target binary from user
   - Validate file exists
   ↓
4. Generate analysis script
   - Create temporary Python script
   - Include Ghidra API calls
   ↓
5. Execute Ghidra headless
   - Build command with parameters
   - Run with 5-minute timeout
   - Capture output
   ↓
6. Parse results
   - Read JSON output
   - Extract analysis data
   ↓
7. Display results
   - Format in Rich table
   - Show function details
```

### Timeout Handling

```python
try:
    result = subprocess.run(
        cmd,
        timeout=300,  # 5 minutes
        capture_output=True,
        text=True
    )
except subprocess.TimeoutExpired:
    return None  # Analysis took too long
```

### Error Handling

The module handles:
- Invalid Ghidra path
- Missing binary file
- Ghidra analysis failures
- Timeout conditions
- JSON parsing errors

## Installation Requirements

### Ghidra Installation

1. **Download Ghidra**: https://ghidra-sre.org/
2. **Install Java JDK 11+** (required by Ghidra)
3. **Extract Ghidra** to desired location
4. **Note path** to `analyzeHeadless` script

### Python Dependencies

All dependencies are included in main `requirements.txt`:
- No additional packages needed

## Use Cases

### 1. Quick Function Overview
Get a rapid overview of all functions in a binary without opening Ghidra GUI.

### 2. Automated Analysis
Integrate into automated malware analysis pipelines.

### 3. Batch Processing
Analyze multiple binaries in sequence.

### 4. API Research
Identify imported APIs and external function calls.

### 5. String Analysis
Extract all strings for reconnaissance.

## Limitations

- Requires Ghidra installation
- Analysis time depends on binary size
- 5-minute timeout for large binaries
- Requires Java runtime (Ghidra dependency)

## Troubleshooting

### "Ghidra path not configured"
- Run "Configure Ghidra Path" option
- Ensure path points to `analyzeHeadless` script

### "Analysis timed out"
- Binary too large (>5 minutes to analyze)
- Try smaller binary or increase timeout in code

### "Failed to parse results"
- Check Ghidra is properly installed
- Verify Java is installed and in PATH
- Check Ghidra version compatibility

### "Permission denied"
- Ensure `analyzeHeadless` is executable
- Run: `chmod +x /path/to/analyzeHeadless`

## Advanced Usage

### Custom Script Generation

You can extend `script_gen.py` to create custom analysis scripts:

```python
def generate_custom_script(self, output_path: Path) -> Path:
    script_content = '''
from ghidra.app.decompiler import DecompInterface
# Your custom Ghidra API calls here
    '''
    script_path = output_path / "custom_script.py"
    script_path.write_text(script_content)
    return script_path
```

### Headless Options

Modify `bridge.py` to add Ghidra headless options:
- `-noanalysis`: Skip automatic analysis
- `-scriptPath`: Add script directory
- `-max-cpu`: Limit CPU usage
- `-loader`: Specify binary loader

## References

- **Ghidra Documentation**: https://ghidra-sre.org/
- **Ghidra Headless Guide**: https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/HeadlessAnalyzer/HeadlessAnalyzer.htm
- **Ghidra API**: https://ghidra.re/ghidra_docs/api/

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Ghidra Bridge  
**Version**: 1.0
