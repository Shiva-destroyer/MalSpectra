"""
MalSpectra - PE Overlay Stripper
Removes overlays (extra data appended to PE files)

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import struct
from pathlib import Path
from typing import Tuple, Dict


class OverlayStripper:
    """
    Handler for detecting and removing PE overlays.
    
    PE overlays are extra data appended after the legitimate PE file,
    often used to hide payloads or additional malware components.
    """
    
    def __init__(self, file_path: str = None):
        """
        Initialize OverlayStripper.
        
        Args:
            file_path: Optional path to PE file
        """
        self.file_path = file_path
    
    def detect_overlay(self) -> Dict:
        """
        Detect overlay in the loaded PE file (instance method).
        
        Returns:
            Dictionary with overlay information
        """
        if self.file_path is None:
            return {'error': 'No file path set'}
        
        # Use static method
        has_overlay, info = self._detect_overlay_static(self.file_path)
        return info
    
    @staticmethod
    def _detect_overlay_static(file_path: str) -> Tuple[bool, Dict]:
        """
        Static method to detect overlay.
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Tuple of (has_overlay, info_dict)
        """
        if not OverlayStripper.is_pe_file(file_path):
            return False, {'error': 'Not a valid PE file'}
        
        pe_size, info = OverlayStripper.calculate_pe_size(file_path)
        
        if 'error' in info:
            return False, info
        
        return info['has_overlay'], info
    
    @staticmethod
    def is_pe_file(file_path: str) -> bool:
        """
        Check if file is a valid PE file.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if valid PE file
        """
        try:
            with open(file_path, 'rb') as f:
                # Check DOS signature
                dos_signature = f.read(2)
                if dos_signature != b'MZ':
                    return False
                
                # Get PE header offset
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                
                # Check PE signature
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return False
                
                return True
        
        except Exception:
            return False
    
    @staticmethod
    def calculate_pe_size(file_path: str) -> Tuple[int, Dict]:
        """
        Calculate the true size of PE file based on headers.
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Tuple of (calculated size, info dict)
        """
        info = {
            'file_size': 0,
            'calculated_pe_size': 0,
            'overlay_size': 0,
            'has_overlay': False,
            'sections': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Get file size
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                info['file_size'] = file_size
                
                # Read DOS header
                f.seek(0)
                dos_header = f.read(64)
                
                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]
                
                # Read PE signature and COFF header
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return 0, {'error': 'Invalid PE signature'}
                
                # Read COFF header (20 bytes)
                coff_header = f.read(20)
                number_of_sections = struct.unpack('<H', coff_header[2:4])[0]
                size_of_optional_header = struct.unpack('<H', coff_header[16:18])[0]
                
                # Skip optional header
                f.seek(pe_offset + 24 + size_of_optional_header)
                
                # Read section headers
                max_end = 0
                for i in range(number_of_sections):
                    section_header = f.read(40)
                    
                    section_name = section_header[0:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    virtual_size = struct.unpack('<I', section_header[8:12])[0]
                    virtual_address = struct.unpack('<I', section_header[12:16])[0]
                    raw_size = struct.unpack('<I', section_header[16:20])[0]
                    raw_address = struct.unpack('<I', section_header[20:24])[0]
                    
                    section_end = raw_address + raw_size
                    if section_end > max_end:
                        max_end = section_end
                    
                    info['sections'].append({
                        'name': section_name,
                        'virtual_size': virtual_size,
                        'raw_size': raw_size,
                        'raw_address': raw_address,
                        'end_offset': section_end
                    })
                
                # Calculate sizes
                info['calculated_pe_size'] = max_end
                info['overlay_size'] = file_size - max_end
                info['has_overlay'] = info['overlay_size'] > 0
                
                return max_end, info
        
        except Exception as e:
            return 0, {'error': f'Error parsing PE: {str(e)}'}
    
    @staticmethod
    def strip_overlay(input_file: str, output_file: str = None, 
                     backup: bool = True) -> Tuple[bool, str]:
        """
        Strip overlay from PE file.
        
        Args:
            input_file: Path to input PE file
            output_file: Path to output file (optional)
            backup: Create backup of original file
            
        Returns:
            Tuple of (success, message)
        """
        # Validate input
        if not os.path.exists(input_file):
            return False, f"Input file not found: {input_file}"
        
        if not OverlayStripper.is_pe_file(input_file):
            return False, "File is not a valid PE file"
        
        # Detect overlay
        has_overlay, info = OverlayStripper.detect_overlay(input_file)
        
        if 'error' in info:
            return False, info['error']
        
        if not has_overlay:
            return False, "No overlay detected in this file"
        
        # Prepare output file
        if output_file is None:
            output_file = input_file + ".stripped"
        
        # Create backup if requested
        if backup:
            backup_file = input_file + ".backup"
            try:
                import shutil
                shutil.copy2(input_file, backup_file)
            except Exception as e:
                return False, f"Failed to create backup: {str(e)}"
        
        # Strip overlay
        try:
            with open(input_file, 'rb') as f_in:
                # Read only the PE portion (without overlay)
                pe_data = f_in.read(info['calculated_pe_size'])
            
            with open(output_file, 'wb') as f_out:
                f_out.write(pe_data)
            
            return True, (f"Successfully stripped overlay!\n"
                        f"Original file: {info['file_size']:,} bytes\n"
                        f"Stripped file: {info['calculated_pe_size']:,} bytes\n"
                        f"Removed overlay: {info['overlay_size']:,} bytes\n"
                        f"Output: {output_file}")
        
        except Exception as e:
            return False, f"Error stripping overlay: {str(e)}"
    
    @staticmethod
    def extract_overlay(input_file: str, output_file: str = None) -> Tuple[bool, str]:
        """
        Extract overlay data to separate file for analysis.
        
        Args:
            input_file: Path to input PE file
            output_file: Path to output overlay file
            
        Returns:
            Tuple of (success, message)
        """
        # Validate input
        if not os.path.exists(input_file):
            return False, f"Input file not found: {input_file}"
        
        if not OverlayStripper.is_pe_file(input_file):
            return False, "File is not a valid PE file"
        
        # Detect overlay
        has_overlay, info = OverlayStripper.detect_overlay(input_file)
        
        if 'error' in info:
            return False, info['error']
        
        if not has_overlay:
            return False, "No overlay detected in this file"
        
        # Prepare output file
        if output_file is None:
            output_file = input_file + ".overlay"
        
        # Extract overlay
        try:
            with open(input_file, 'rb') as f_in:
                # Seek to overlay start
                f_in.seek(info['calculated_pe_size'])
                overlay_data = f_in.read()
            
            with open(output_file, 'wb') as f_out:
                f_out.write(overlay_data)
            
            return True, (f"Successfully extracted overlay!\n"
                        f"Overlay size: {info['overlay_size']:,} bytes\n"
                        f"Output: {output_file}")
        
        except Exception as e:
            return False, f"Error extracting overlay: {str(e)}"
    
    @staticmethod
    def analyze_overlay(file_path: str) -> Dict:
        """
        Analyze overlay content for common patterns.
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Dictionary with overlay analysis
        """
        has_overlay, info = OverlayStripper.detect_overlay(file_path)
        
        if not has_overlay or 'error' in info:
            return info
        
        analysis = info.copy()
        
        try:
            with open(file_path, 'rb') as f:
                # Read overlay
                f.seek(info['calculated_pe_size'])
                overlay_data = f.read(min(1024, info['overlay_size']))  # Read first 1KB
                
                # Check for common patterns
                patterns = {
                    'ZIP': overlay_data.startswith(b'PK\x03\x04'),
                    'RAR': overlay_data.startswith(b'Rar!\x1a'),
                    'PDF': overlay_data.startswith(b'%PDF'),
                    'JPEG': overlay_data.startswith(b'\xff\xd8\xff'),
                    'PNG': overlay_data.startswith(b'\x89PNG'),
                    'MZ (PE)': overlay_data.startswith(b'MZ'),
                    'All NULL': all(b == 0 for b in overlay_data[:100]),
                    'All 0xFF': all(b == 0xFF for b in overlay_data[:100]),
                }
                
                detected_formats = [fmt for fmt, found in patterns.items() if found]
                analysis['detected_formats'] = detected_formats if detected_formats else ['Unknown/Custom']
                
                # Calculate entropy of overlay
                from collections import Counter
                import math
                
                byte_counts = Counter(overlay_data)
                entropy = 0.0
                for count in byte_counts.values():
                    probability = count / len(overlay_data)
                    entropy -= probability * math.log2(probability)
                
                analysis['overlay_entropy'] = entropy
                
                if entropy >= 7.5:
                    analysis['overlay_assessment'] = 'Likely encrypted/compressed'
                elif entropy >= 6.0:
                    analysis['overlay_assessment'] = 'Possibly compressed'
                else:
                    analysis['overlay_assessment'] = 'Plain data'
        
        except Exception as e:
            analysis['analysis_error'] = str(e)
        
        return analysis
