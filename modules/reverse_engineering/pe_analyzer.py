"""
MalSpectra - PE Analyzer Module
Advanced Portable Executable (PE) File Analysis

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import pefile
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict


class PEAnalyzer:
    """
    Advanced PE file analyzer for malware reverse engineering.
    Analyzes headers, security features, imports, and entropy.
    """
    
    def __init__(self, file_path: str):
        """
        Initialize PE analyzer with target file.
        
        Args:
            file_path: Path to the PE file to analyze
        
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
    
    def analyze_headers(self) -> Dict[str, Any]:
        """
        Analyze DOS, File, and Optional headers.
        
        Returns:
            Dictionary containing header information
        """
        headers = {}
        
        # DOS Header
        headers['dos_header'] = {
            'magic': hex(self.pe.DOS_HEADER.e_magic),
            'lfanew': hex(self.pe.DOS_HEADER.e_lfanew)
        }
        
        # NT Headers - File Header
        headers['file_header'] = {
            'machine': hex(self.pe.FILE_HEADER.Machine),
            'machine_type': self._get_machine_type(self.pe.FILE_HEADER.Machine),
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
            'characteristics': hex(self.pe.FILE_HEADER.Characteristics)
        }
        
        # Optional Header
        headers['optional_header'] = {
            'magic': hex(self.pe.OPTIONAL_HEADER.Magic),
            'architecture': '64-bit' if self.pe.OPTIONAL_HEADER.Magic == 0x20b else '32-bit',
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'section_alignment': hex(self.pe.OPTIONAL_HEADER.SectionAlignment),
            'file_alignment': hex(self.pe.OPTIONAL_HEADER.FileAlignment),
            'subsystem': self._get_subsystem(self.pe.OPTIONAL_HEADER.Subsystem),
            'dll_characteristics': hex(self.pe.OPTIONAL_HEADER.DllCharacteristics)
        }
        
        return headers
    
    def check_security(self) -> Dict[str, Any]:
        """
        Check security features: ASLR, DEP, NX, SafeSEH.
        
        Returns:
            Dictionary with security feature status
        """
        security = {}
        
        # DLL Characteristics flags
        dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics
        
        # ASLR - Address Space Layout Randomization
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        security['ASLR'] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        
        # DEP/NX - Data Execution Prevention / No Execute
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
        security['DEP/NX'] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        
        # SEH - Structured Exception Handling
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
        security['SafeSEH'] = not bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        
        # Control Flow Guard
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
        security['CFG'] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        
        # High Entropy VA (64-bit ASLR)
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
        security['High_Entropy_VA'] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
        
        # Calculate security score
        enabled_features = sum(1 for v in security.values() if v)
        total_features = len(security)
        security['security_score'] = f"{enabled_features}/{total_features}"
        
        return security
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """
        Extract imported DLLs and functions.
        
        Returns:
            List of dictionaries containing import information
        """
        imports = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_imports = {
                'dll': entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll,
                'functions': []
            }
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                    dll_imports['functions'].append({
                        'name': func_name,
                        'address': hex(imp.address) if imp.address else 'N/A'
                    })
                else:
                    dll_imports['functions'].append({
                        'name': f'Ordinal_{imp.ordinal}',
                        'address': hex(imp.address) if imp.address else 'N/A'
                    })
            
            imports.append(dll_imports)
        
        return imports
    
    def calculate_entropy(self) -> List[Dict[str, Any]]:
        """
        Calculate Shannon entropy for each section.
        High entropy (> 7.0) may indicate encryption/packing.
        
        Returns:
            List of sections with entropy values
        """
        sections = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            section_data = section.get_data()
            
            # Calculate Shannon entropy
            entropy = self._calculate_shannon_entropy(section_data)
            
            # Determine suspicion level
            if entropy > 7.0:
                suspicion = "High (Packed/Encrypted)"
                risk = "CRITICAL"
            elif entropy > 6.5:
                suspicion = "Medium (Compressed)"
                risk = "WARNING"
            else:
                suspicion = "Low (Normal)"
                risk = "SAFE"
            
            sections.append({
                'name': section_name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(entropy, 3),
                'suspicion': suspicion,
                'risk': risk
            })
        
        return sections
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Byte data to analyze
        
        Returns:
            Entropy value (0-8)
        """
        if not data:
            return 0.0
        
        # Count byte frequency
        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _get_machine_type(self, machine: int) -> str:
        """Get human-readable machine type."""
        machine_types = {
            0x14c: 'i386',
            0x8664: 'AMD64',
            0x1c0: 'ARM',
            0xaa64: 'ARM64',
            0x1a2: 'SH3',
            0x1a6: 'SH4',
            0x1c2: 'THUMB'
        }
        return machine_types.get(machine, 'Unknown')
    
    def _get_subsystem(self, subsystem: int) -> str:
        """Get human-readable subsystem type."""
        subsystems = {
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows CUI',
            7: 'POSIX CUI',
            9: 'Windows CE GUI',
            10: 'EFI Application',
            11: 'EFI Boot Service Driver',
            12: 'EFI Runtime Driver',
            13: 'EFI ROM',
            14: 'XBOX'
        }
        return subsystems.get(subsystem, 'Unknown')
    
    def get_file_info(self) -> Dict[str, Any]:
        """
        Get basic file information.
        
        Returns:
            Dictionary with file metadata
        """
        return {
            'filename': self.file_path.name,
            'size': self.file_path.stat().st_size,
            'path': str(self.file_path.absolute())
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
