"""
MalSpectra - Disassembler Module
Binary Disassembly using Capstone Engine

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import pefile
import capstone
from pathlib import Path
from typing import List, Dict, Any, Optional


class Disassembler:
    """
    Disassemble PE files using Capstone disassembly engine.
    Focuses on entry point analysis for malware behavior detection.
    """
    
    def __init__(self, file_path: str):
        """
        Initialize disassembler with target PE file.
        
        Args:
            file_path: Path to the PE file
        
        Raises:
            FileNotFoundError: If file doesn't exist
            pefile.PEFormatError: If file is not a valid PE
        """
        self.file_path = Path(file_path)
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            self.pe = pefile.PE(str(self.file_path))
        except pefile.PEFormatError as e:
            raise pefile.PEFormatError(f"Invalid PE file: {str(e)}")
        
        # Determine architecture and setup Capstone
        self._setup_capstone()
    
    def _setup_capstone(self):
        """Setup Capstone disassembler based on PE architecture."""
        # Check if 32-bit or 64-bit
        if self.pe.OPTIONAL_HEADER.Magic == 0x20b:  # PE32+
            self.arch = 'x64'
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:  # PE32
            self.arch = 'x86'
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        
        # Set disassembly options
        self.md.detail = True
        self.md.skipdata = True
    
    def disassemble_entry_point(self, num_bytes: int = 64) -> List[Dict[str, Any]]:
        """
        Disassemble code at the entry point.
        
        Args:
            num_bytes: Number of bytes to disassemble (default: 64)
        
        Returns:
            List of disassembled instructions
        """
        try:
            # Get entry point address
            entry_point_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point_offset = self.pe.get_offset_from_rva(entry_point_rva)
            
            # Read code from entry point
            code = self.pe.get_data(entry_point_rva, num_bytes)
            
            # Disassemble
            instructions = []
            for instr in self.md.disasm(code, self.pe.OPTIONAL_HEADER.ImageBase + entry_point_rva):
                instructions.append({
                    'address': hex(instr.address),
                    'mnemonic': instr.mnemonic,
                    'operands': instr.op_str,
                    'bytes': ' '.join(f'{b:02x}' for b in instr.bytes),
                    'size': instr.size
                })
            
            return instructions
        
        except Exception as e:
            raise RuntimeError(f"Disassembly failed: {str(e)}")
    
    def analyze_instructions(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze disassembled instructions for suspicious patterns.
        
        Args:
            instructions: List of disassembled instructions
        
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'total_instructions': len(instructions),
            'suspicious_patterns': [],
            'api_calls': [],
            'jumps': 0,
            'calls': 0
        }
        
        # Suspicious instruction patterns
        suspicious_mnemonics = {
            'int': 'Interrupt (possible anti-debug)',
            'rdtsc': 'Timestamp counter (timing check)',
            'cpuid': 'CPU ID (VM detection)',
            'in': 'Port I/O (low-level access)',
            'out': 'Port I/O (low-level access)'
        }
        
        for instr in instructions:
            mnemonic = instr['mnemonic']
            
            # Check for suspicious instructions
            if mnemonic in suspicious_mnemonics:
                analysis['suspicious_patterns'].append({
                    'instruction': f"{mnemonic} {instr['operands']}",
                    'reason': suspicious_mnemonics[mnemonic],
                    'address': instr['address']
                })
            
            # Count control flow instructions
            if mnemonic.startswith('j'):  # Jumps (jmp, je, jne, etc.)
                analysis['jumps'] += 1
            elif mnemonic == 'call':
                analysis['calls'] += 1
                analysis['api_calls'].append({
                    'address': instr['address'],
                    'target': instr['operands']
                })
        
        return analysis
    
    def get_entry_point_info(self) -> Dict[str, Any]:
        """
        Get entry point information.
        
        Returns:
            Dictionary with entry point details
        """
        entry_point_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = self.pe.OPTIONAL_HEADER.ImageBase + entry_point_rva
        entry_point_offset = self.pe.get_offset_from_rva(entry_point_rva)
        
        # Find which section contains the entry point
        section_name = "Unknown"
        for section in self.pe.sections:
            if section.VirtualAddress <= entry_point_rva < (section.VirtualAddress + section.Misc_VirtualSize):
                section_name = section.Name.decode('utf-8').strip('\x00')
                break
        
        return {
            'rva': hex(entry_point_rva),
            'virtual_address': hex(entry_point_va),
            'file_offset': hex(entry_point_offset),
            'section': section_name,
            'architecture': self.arch
        }
    
    def close(self):
        """Close PE file handle."""
        if hasattr(self, 'pe') and self.pe:
            self.pe.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
