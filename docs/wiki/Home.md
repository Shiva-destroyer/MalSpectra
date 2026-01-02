# 🛡️ MalSpectra Wiki - Home

Welcome to the **MalSpectra** documentation! This comprehensive framework provides 12 advanced modules for malware analysis, reverse engineering, and cybersecurity research.

---

## 📚 Table of Contents

### Core Modules

1. **[Reverse Engineering](01_Reverse_Engineering.md)** - Static analysis & entropy detection
2. **[Ghidra Bridge](02_Ghidra_Bridge.md)** - Automated decompilation & analysis
3. **[Dynamic Sandbox](03_Malware_Sandbox.md)** - Behavioral analysis & monitoring
4. **[Signature Generator](04_Signature_Generator.md)** - YARA rule creation from samples
5. **[API Hooking](05_API_Hooking.md)** - Runtime function interception
6. **[Code Injection](06_Code_Injection.md)** - Process injection techniques
7. **[Rootkit Analysis](07_Rootkit_Analysis.md)** - Kernel-level threat detection
8. **[Botnet Analyzer](08_Botnet_Analyzer.md)** - Network traffic analysis
9. **[Ransomware Helper](09_Ransomware_Helper.md)** - Encryption analysis toolkit
10. **[Worm Propagation Simulator](10_Worm_Simulator.md)** - Network propagation modeling
11. **[Trojan Detection System](11_Trojan_Detection.md)** - Behavior-based classification
12. **[Malware Packer/Unpacker](12_Packer_Unpacker.md)** - PE packing detection & removal

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Shiva-destroyer/MalSpectra.git
cd MalSpectra

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run MalSpectra
python3 main.py
```

---

## 🎯 Framework Architecture

MalSpectra follows a modular design with three core layers:

### 1. **Core Layer** (`core/`)
- **Config Management** - Centralized configuration system
- **Logger** - Comprehensive logging with file rotation
- **Utilities** - Shared helper functions

### 2. **Modules Layer** (`modules/`)
- **12 Independent Modules** - Each with isolated functionality
- **Standardized Interface** - `run()` entry point for all modules
- **Error Handling** - Graceful failure with detailed diagnostics

### 3. **Testing Layer** (`tests/`)
- **Unit Tests** - 44 comprehensive test cases
- **Integration Tests** - Module interaction validation
- **UAT Suite** - 36 user acceptance scenarios

---

## 📖 How to Use This Wiki

Each module page contains:

- **Overview** - What the module does
- **The Algorithm** - Mathematical/logical foundation
- **Implementation** - Technical details & dependencies
- **Unique Features** - What makes it special
- **Pros & Cons** - Honest evaluation
- **Usage** - Step-by-step examples

---

## ⚠️ Important Notes

### Educational Purpose
MalSpectra is designed for **educational and research purposes only**. Always:
- Use in isolated environments (VMs/sandboxes)
- Comply with local laws and regulations
- Obtain proper authorization before testing
- Never use on production systems without consent

### System Requirements
- **OS**: Linux (Ubuntu 20.04+) or Windows 10/11
- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 2GB free space

### Dependencies
- `pefile` - PE file parsing
- `yara-python` - Pattern matching
- `capstone` - Disassembly engine
- `rich` - Terminal UI
- `scapy` - Network analysis

---

## 🧑‍💻 Developer Information

**Developer**: Sai Srujan Murthy  
**Contact**: saisrujanmurthy@gmail.com  
**License**: MIT  
**Version**: v1.0 FINAL

---

## 🔗 Additional Resources

- **[GitHub Repository](https://github.com/Shiva-destroyer/MalSpectra)**
- **[Installation Guide](../installation.md)**
- **[Troubleshooting](../troubleshooting.md)**

---

## 🛠️ Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

---

**Last Updated**: January 3, 2026  
**Framework Status**: Production Ready ✅
