"""
MalSpectra - YARA Rule Builder
Automatically generates YARA rules from binary files

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import re
import string
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime


class YaraBuilder:
    """
    Builds YARA rules from binary files by extracting:
    - ASCII and Unicode strings
    - Opcodes from entry point
    - Metadata information
    """
    
    def __init__(self, file_path: str):
        """
        Initialize YARA builder.
        
        Args:
            file_path: Path to binary file
        """
        self.file_path = Path(file_path)
        self.binary_data = None
        self.strings = []
        self.opcodes = []
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read binary data
        with open(self.file_path, 'rb') as f:
            self.binary_data = f.read()
    
    def extract_strings(self, min_length: int = 4, max_strings: int = 20) -> List[str]:
        """
        Extract ASCII and Unicode strings from binary.
        
        Args:
            min_length: Minimum string length to consider
            max_strings: Maximum number of strings to extract
            
        Returns:
            List of extracted strings
        """
        strings_found = []
        
        # Extract ASCII strings
        ascii_pattern = b'[\x20-\x7e]{' + str(min_length).encode() + b',}'
        ascii_matches = re.findall(ascii_pattern, self.binary_data)
        
        for match in ascii_matches:
            try:
                decoded = match.decode('ascii')
                # Filter out common garbage
                if self._is_valid_string(decoded):
                    strings_found.append(decoded)
            except UnicodeDecodeError:
                continue
        
        # Extract Unicode strings (UTF-16LE)
        try:
            unicode_pattern = b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}'
            unicode_matches = re.findall(unicode_pattern, self.binary_data)
            
            for match in unicode_matches:
                try:
                    decoded = match.decode('utf-16le')
                    if self._is_valid_string(decoded):
                        strings_found.append(decoded)
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass
        
        # Remove duplicates and limit
        unique_strings = list(set(strings_found))
        unique_strings.sort(key=len, reverse=True)  # Longer strings first
        
        self.strings = unique_strings[:max_strings]
        return self.strings
    
    def _is_valid_string(self, s: str) -> bool:
        """
        Check if string is valid (not garbage).
        
        Args:
            s: String to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Filter out strings that are all the same character
        if len(set(s)) < 2:
            return False
        
        # Filter out strings with too many non-alphanumeric chars
        alphanum_count = sum(c.isalnum() for c in s)
        if alphanum_count / len(s) < 0.4:
            return False
        
        # Filter out common paths/system strings that are too generic
        common_garbage = [
            'This program cannot be run in DOS mode',
            '!This program must be run under Win32',
            'LoadLibrary',
            'GetProcAddress',
            'VirtualAlloc'
        ]
        
        for garbage in common_garbage:
            if garbage in s:
                return False
        
        return True
    
    def extract_opcodes(self, num_bytes: int = 20) -> str:
        """
        Extract opcodes from the beginning of the file.
        For PE files, this would be from the entry point.
        For simplicity, we take the first N bytes.
        
        Args:
            num_bytes: Number of bytes to extract
            
        Returns:
            Hex string of opcodes
        """
        # Try to find PE entry point if it's a PE file
        entry_point_offset = 0
        
        # Check for PE signature
        if self.binary_data[:2] == b'MZ':
            try:
                # Simple PE parsing for entry point
                # This is a simplified approach
                e_lfanew = int.from_bytes(self.binary_data[0x3c:0x40], 'little')
                if e_lfanew < len(self.binary_data) - 100:
                    # Check PE signature
                    if self.binary_data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                        # Read AddressOfEntryPoint (offset 0x28 from PE header)
                        entry_point_rva = int.from_bytes(
                            self.binary_data[e_lfanew+0x28:e_lfanew+0x2c], 'little'
                        )
                        
                        # For simplicity, use RVA as offset
                        # (proper implementation would need section mapping)
                        if entry_point_rva < len(self.binary_data):
                            entry_point_offset = entry_point_rva
            except Exception:
                pass
        
        # Extract bytes
        opcodes_bytes = self.binary_data[entry_point_offset:entry_point_offset + num_bytes]
        
        # Convert to hex string
        hex_string = ' '.join(f'{b:02x}' for b in opcodes_bytes)
        self.opcodes = hex_string
        
        return hex_string
    
    def build_rule(self, rule_name: Optional[str] = None) -> str:
        """
        Build complete YARA rule.
        
        Args:
            rule_name: Name for the YARA rule (defaults to filename)
            
        Returns:
            YARA rule as string
        """
        if not rule_name:
            rule_name = self.file_path.stem.replace('-', '_').replace('.', '_')
            rule_name = ''.join(c for c in rule_name if c.isalnum() or c == '_')
            if not rule_name[0].isalpha():
                rule_name = 'rule_' + rule_name
        
        # Ensure strings are extracted
        if not self.strings:
            self.extract_strings()
        
        # Ensure opcodes are extracted
        if not self.opcodes:
            self.extract_opcodes()
        
        # Build YARA rule
        rule_lines = []
        
        # Rule header
        rule_lines.append(f'rule {rule_name}')
        rule_lines.append('{')
        
        # Meta section
        rule_lines.append('    meta:')
        rule_lines.append(f'        description = "Auto-generated YARA rule for {self.file_path.name}"')
        rule_lines.append(f'        author = "MalSpectra - Sai Srujan Murthy"')
        rule_lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')
        rule_lines.append(f'        hash = "Generated from {self.file_path.name}"')
        rule_lines.append('')
        
        # Strings section
        rule_lines.append('    strings:')
        
        # Add opcodes as hex pattern
        if self.opcodes:
            rule_lines.append(f'        $opcode = {{ {self.opcodes} }}')
        
        # Add extracted strings
        for i, s in enumerate(self.strings[:10], 1):  # Limit to 10 strings
            # Escape special characters for YARA
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            rule_lines.append(f'        $str{i} = "{escaped}" ascii wide')
        
        rule_lines.append('')
        
        # Condition section
        rule_lines.append('    condition:')
        
        # Build condition
        if self.opcodes and len(self.strings) > 0:
            rule_lines.append('        $opcode or')
            rule_lines.append(f'        {len(self.strings)} of ($str*)')
        elif self.opcodes:
            rule_lines.append('        $opcode')
        elif len(self.strings) > 0:
            rule_lines.append(f'        {max(1, len(self.strings) // 2)} of ($str*)')
        else:
            rule_lines.append('        true')
        
        rule_lines.append('}')
        
        return '\n'.join(rule_lines)
    
    def save_rule(self, output_path: str) -> None:
        """
        Save YARA rule to file.
        
        Args:
            output_path: Path to save the rule
        """
        rule_content = self.build_rule()
        
        output_file = Path(output_path)
        output_file.write_text(rule_content)


if __name__ == "__main__":
    # Test YARA builder
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python yara_builder.py <binary_file>")
        sys.exit(1)
    
    try:
        builder = YaraBuilder(sys.argv[1])
        
        print(f"Extracting strings from {sys.argv[1]}...")
        strings = builder.extract_strings()
        print(f"Found {len(strings)} strings")
        
        print(f"\nExtracting opcodes...")
        opcodes = builder.extract_opcodes()
        print(f"Opcodes: {opcodes[:50]}...")
        
        print(f"\nGenerating YARA rule...")
        rule = builder.build_rule()
        print(rule)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
