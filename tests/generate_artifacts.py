#!/usr/bin/env python3
"""
MalSpectra Test Artifact Generator

Generates safe dummy test files for testing all 12 modules.
NO REAL MALWARE - All artifacts are harmless test data.

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
import struct
import random
from pathlib import Path

# Try importing optional dependencies
try:
    from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available - PCAP generation will be skipped")


class TestArtifactGenerator:
    """Generates safe test artifacts for MalSpectra testing."""
    
    def __init__(self, output_dir: str = "data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_minimal_pe(self, filename: str = "test_malware.exe") -> Path:
        """
        Generate a minimal but valid PE executable structure.
        This is NOT real malware - just a PE skeleton for parser testing.
        """
        filepath = self.output_dir / filename
        
        # DOS Header (64 bytes)
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'  # Magic number
        dos_header[0x3C:0x40] = struct.pack('<I', 0x80)  # PE offset at 128 bytes
        
        # DOS Stub (64 bytes padding)
        dos_stub = b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21' + b'\x00' * 50
        
        # PE Signature (4 bytes)
        pe_signature = b'PE\x00\x00'
        
        # COFF File Header (20 bytes)
        coff_header = struct.pack(
            '<HHIIIHH',
            0x014C,     # Machine (x86)
            3,          # NumberOfSections
            0x12345678, # TimeDateStamp (dummy)
            0,          # PointerToSymbolTable
            0,          # NumberOfSymbols
            224,        # SizeOfOptionalHeader
            0x0102      # Characteristics (executable, 32-bit)
        )
        
        # Simplified Optional Header
        # Format: H=ushort(2), B=byte(1), I=uint(4)
        # Total 22 values matching format string '<HHBBIIIIIIIHHHHHHIIIHH'
        optional_header = struct.pack(
            '<HHBBIIIIIIIHHHHHHIIIHH',
            0x010B,     # H: Magic (PE32)
            0x0E,       # H: MajorLinkerVersion
            0x00,       # B: MinorLinkerVersion
            0,          # B: padding
            0x1000,     # I: SizeOfCode
            0x1000,     # I: SizeOfInitializedData
            0,          # I: SizeOfUninitializedData
            0x1000,     # I: AddressOfEntryPoint
            0x1000,     # I: BaseOfCode
            0x2000,     # I: BaseOfData
            0x400000,   # I: ImageBase
            0x1000,     # H: SectionAlignment
            0x200,      # H: FileAlignment
            6,          # H: OS Version Major
            0,          # H: OS Version Minor
            6,          # H: Image Version Major
            0,          # H: Image Version Minor
            0x10000,    # I: SizeOfImage
            0x400,      # I: SizeOfHeaders
            0,          # I: CheckSum
            3,          # H: Subsystem (CONSOLE)
            0           # H: DllCharacteristics
        )
        # Pad to 224 bytes
        optional_header += b'\x00' * (224 - len(optional_header))
        
        # Section Headers (3 sections, 40 bytes each)
        sections = []
        
        # .text section
        text_section = struct.pack(
            '<8sIIIIIIHHI',
            b'.text\x00\x00\x00',  # Name
            0x1000,     # VirtualSize
            0x1000,     # VirtualAddress
            0x200,      # SizeOfRawData
            0x400,      # PointerToRawData
            0, 0, 0, 0, # Relocations, Linenumbers
            0x60000020  # Characteristics (code, executable, readable)
        )
        sections.append(text_section)
        
        # .data section
        data_section = struct.pack(
            '<8sIIIIIIHHI',
            b'.data\x00\x00\x00',
            0x1000,     # VirtualSize
            0x2000,     # VirtualAddress
            0x200,      # SizeOfRawData
            0x600,      # PointerToRawData
            0, 0, 0, 0,
            0xC0000040  # Characteristics (initialized data, readable, writable)
        )
        sections.append(data_section)
        
        # .rsrc section
        rsrc_section = struct.pack(
            '<8sIIIIIIHHI',
            b'.rsrc\x00\x00\x00',
            0x1000,     # VirtualSize
            0x3000,     # VirtualAddress
            0x200,      # SizeOfRawData
            0x800,      # PointerToRawData
            0, 0, 0, 0,
            0x40000040  # Characteristics (initialized data, readable)
        )
        sections.append(rsrc_section)
        
        # Combine headers
        headers = dos_header + dos_stub + pe_signature + coff_header + optional_header
        for section in sections:
            headers += section
        
        # Pad headers to 0x400 (1024 bytes)
        headers += b'\x00' * (0x400 - len(headers))
        
        # .text section content (0x200 bytes)
        text_content = b'\x90' * 0x200  # NOP sled (harmless)
        
        # .data section content (0x200 bytes)
        data_content = b'TEST DATA FOR MALSPECTRA\x00' * 13
        data_content = data_content[:0x200]
        
        # .rsrc section content (0x200 bytes)
        rsrc_content = b'\x00' * 0x200
        
        # Add overlay (512 bytes of random data for overlay testing)
        overlay = bytes([random.randint(0, 255) for _ in range(512)])
        
        # Write complete PE file
        with open(filepath, 'wb') as f:
            f.write(headers)
            f.write(text_content)
            f.write(data_content)
            f.write(rsrc_content)
            f.write(overlay)  # This creates a detectable overlay
        
        print(f"✓ Generated minimal PE: {filepath} ({os.path.getsize(filepath)} bytes)")
        print(f"  - DOS Header: MZ signature")
        print(f"  - PE Signature: PE\\0\\0")
        print(f"  - Sections: .text, .data, .rsrc")
        print(f"  - Overlay: 512 bytes (for testing overlay detection)")
        
        return filepath
    
    def generate_suspicious_traffic(self, filename: str = "test_traffic.pcap") -> Path:
        """
        Generate a PCAP file with suspicious DNS traffic.
        Uses Scapy to create realistic packet captures.
        """
        filepath = self.output_dir / filename
        
        if not SCAPY_AVAILABLE:
            # Create empty file as placeholder
            filepath.touch()
            print(f"⚠️  Skipped PCAP generation (scapy not available): {filepath}")
            return filepath
        
        packets = []
        
        # Suspicious DNS queries (C2 domains, DGA-like)
        suspicious_domains = [
            "malware-c2.com",
            "evil-server.net",
            "botnet-command.org",
            "ransomware-payment.onion.to",
            "crypto-miner-pool.xyz",
            "phishing-site.tk",
            "trojan-download.ml"
        ]
        
        for i, domain in enumerate(suspicious_domains):
            # DNS Query packet
            pkt = Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
            packets.append(pkt)
        
        # Write PCAP
        wrpcap(str(filepath), packets)
        
        print(f"✓ Generated PCAP: {filepath} ({len(packets)} packets)")
        print(f"  - Suspicious DNS queries: {len(suspicious_domains)}")
        print(f"  - Domains: malware-c2.com, evil-server.net, etc.")
        
        return filepath
    
    def generate_encrypted_file(self, filename: str = "test_ransom.locked") -> Path:
        """
        Generate a file with high entropy (simulates encrypted/ransomware file).
        """
        filepath = self.output_dir / filename
        
        # Generate random bytes (high entropy)
        size = 4096  # 4 KB
        random_data = bytes([random.randint(0, 255) for _ in range(size)])
        
        with open(filepath, 'wb') as f:
            f.write(random_data)
        
        # Calculate Shannon entropy
        from collections import Counter
        import math
        
        counter = Counter(random_data)
        total = len(random_data)
        entropy = -sum((count/total) * math.log2(count/total) for count in counter.values())
        
        print(f"✓ Generated encrypted file: {filepath} ({size} bytes)")
        print(f"  - Entropy: {entropy:.2f} / 8.00 (high entropy = encrypted)")
        print(f"  - Simulates ransomware-encrypted file")
        
        return filepath
    
    def generate_test_script(self, filename: str = "test_script.py") -> Path:
        """
        Generate a harmless Python script for sandbox testing.
        """
        filepath = self.output_dir / filename
        
        script_content = '''#!/usr/bin/env python3
"""
Harmless test script for MalSpectra sandbox testing.
This script performs safe operations for testing purposes.
"""

import os
import time

def main():
    """Safe test operations."""
    print("Test script started")
    
    # File operation (harmless)
    test_file = "/tmp/malspectra_test.txt"
    with open(test_file, 'w') as f:
        f.write("MalSpectra test data\\n")
    
    # Read back
    with open(test_file, 'r') as f:
        content = f.read()
        print(f"Read: {content.strip()}")
    
    # Sleep briefly
    time.sleep(0.5)
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
        print("Cleaned up test file")
    
    print("Test script completed successfully")

if __name__ == "__main__":
    main()
'''
        
        with open(filepath, 'w') as f:
            f.write(script_content)
        
        # Make executable
        os.chmod(filepath, 0o755)
        
        print(f"✓ Generated test script: {filepath}")
        print(f"  - Harmless Python script for sandbox testing")
        print(f"  - Operations: file write, read, cleanup")
        
        return filepath
    
    def generate_packed_sample(self, filename: str = "test_packed.exe") -> Path:
        """
        Generate a PE file that looks packed (high entropy in code section).
        """
        filepath = self.output_dir / filename
        
        # Start with basic PE structure
        base_pe = self.generate_minimal_pe(filename)
        
        # Read it back
        with open(base_pe, 'rb') as f:
            data = bytearray(f.read())
        
        # Replace .text section with high-entropy data (simulates packing)
        # .text starts at 0x400, size 0x200
        text_start = 0x400
        text_size = 0x200
        
        # Generate high-entropy data
        packed_data = bytes([random.randint(0, 255) for _ in range(text_size)])
        data[text_start:text_start+text_size] = packed_data
        
        # Write modified PE
        with open(filepath, 'wb') as f:
            f.write(data)
        
        print(f"✓ Generated packed PE: {filepath}")
        print(f"  - High entropy .text section (simulates UPX/packing)")
        
        return filepath
    
    def generate_trojan_sample(self, filename: str = "test_trojan.exe") -> Path:
        """
        Generate a PE with suspicious API imports (for trojan detection testing).
        """
        filepath = self.output_dir / filename
        
        # For simplicity, use the basic PE and add suspicious strings
        base_pe = self.generate_minimal_pe(filename)
        
        # Read it back
        with open(base_pe, 'rb') as f:
            data = bytearray(f.read())
        
        # Add suspicious strings to .data section
        suspicious_strings = [
            b"GetAsyncKeyState\x00",
            b"SetWindowsHookEx\x00",
            b"InternetOpen\x00",
            b"socket\x00",
            b"RegCreateKey\x00",
            b"cmd.exe /c\x00",
            b"192.168.1.100:5552\x00",  # C2 address
            b"password\x00",
            b"keylog\x00"
        ]
        
        # .data starts at 0x600
        data_start = 0x600
        offset = data_start
        
        for string in suspicious_strings:
            if offset + len(string) < data_start + 0x200:
                data[offset:offset+len(string)] = string
                offset += len(string)
        
        # Write modified PE
        with open(filepath, 'wb') as f:
            f.write(data)
        
        print(f"✓ Generated trojan sample: {filepath}")
        print(f"  - Contains suspicious strings/APIs for detection testing")
        
        return filepath
    
    def generate_all(self):
        """Generate all test artifacts."""
        print("=" * 70)
        print("MalSpectra Test Artifact Generator")
        print("Developer: Sai Srujan Murthy (saisrujanmurthy@gmail.com)")
        print("=" * 70)
        print()
        
        artifacts = []
        
        # Generate each artifact
        artifacts.append(self.generate_minimal_pe())
        artifacts.append(self.generate_suspicious_traffic())
        artifacts.append(self.generate_encrypted_file())
        artifacts.append(self.generate_test_script())
        artifacts.append(self.generate_packed_sample())
        artifacts.append(self.generate_trojan_sample())
        
        print()
        print("=" * 70)
        print(f"✓ Generated {len(artifacts)} test artifacts in {self.output_dir}/")
        print("=" * 70)
        print()
        print("⚠️  REMINDER: These are SAFE test files, NOT real malware!")
        print("   - test_malware.exe: Minimal PE structure (harmless)")
        print("   - test_traffic.pcap: Simulated suspicious DNS traffic")
        print("   - test_ransom.locked: High-entropy file (random bytes)")
        print("   - test_script.py: Harmless Python script")
        print("   - test_packed.exe: PE with high-entropy section")
        print("   - test_trojan.exe: PE with suspicious strings")
        print()
        
        return artifacts


def main():
    """Main entry point."""
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    # Generate artifacts
    generator = TestArtifactGenerator(output_dir="data")
    generator.generate_all()


if __name__ == "__main__":
    main()
