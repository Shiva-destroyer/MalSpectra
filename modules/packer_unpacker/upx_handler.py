"""
MalSpectra - UPX Packer/Unpacker Handler
Wrapper for UPX (Ultimate Packer for eXecutables)

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Tuple, Dict


class UPXHandler:
    """
    Handler for UPX packer/unpacker operations.
    Provides safe interface to UPX command-line tool.
    """
    
    def __init__(self):
        """Initialize UPX handler."""
        self.upx_path = self._find_upx()
    
    def _find_upx(self) -> str:
        """
        Locate UPX executable on the system.
        
        Returns:
            Path to UPX binary or None
        """
        # Check if upx is in PATH
        upx_path = shutil.which('upx')
        if upx_path:
            return upx_path
        
        # Check common installation locations
        common_paths = [
            '/usr/bin/upx',
            '/usr/local/bin/upx',
            'C:\\Program Files\\upx\\upx.exe',
            'C:\\upx\\upx.exe'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def is_upx_available(self) -> bool:
        """
        Check if UPX is installed and accessible.
        
        Returns:
            True if UPX is available
        """
        return self.upx_path is not None
    
    def get_upx_version(self) -> str:
        """
        Get UPX version information.
        
        Returns:
            Version string or error message
        """
        if not self.is_upx_available():
            return "UPX not found"
        
        try:
            result = subprocess.run(
                [self.upx_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse version from output
            version_line = result.stdout.split('\n')[0]
            return version_line.strip()
        
        except Exception as e:
            return f"Error getting version: {str(e)}"
    
    def is_upx_packed(self, file_path: str) -> bool:
        """
        Check if a file is UPX packed.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if file appears to be UPX packed
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
            
            # Look for UPX signatures
            upx_signatures = [
                b'UPX!',
                b'UPX0',
                b'UPX1',
                b'UPX2'
            ]
            
            for sig in upx_signatures:
                if sig in data:
                    return True
            
            return False
        
        except Exception:
            return False
    
    def pack_binary(self, input_file: str, output_file: str = None, 
                   compression_level: int = 9) -> Tuple[bool, str]:
        """
        Pack a binary file using UPX.
        
        Args:
            input_file: Path to input file
            output_file: Path to output file (optional)
            compression_level: Compression level 1-9 (default: 9 = best)
            
        Returns:
            Tuple of (success, message)
        """
        if not self.is_upx_available():
            return False, "UPX is not installed. Install from: https://upx.github.io/"
        
        if not os.path.exists(input_file):
            return False, f"Input file not found: {input_file}"
        
        # Check if already packed
        if self.is_upx_packed(input_file):
            return False, "File is already UPX packed"
        
        # Prepare output file
        if output_file is None:
            output_file = input_file + ".packed"
        
        # Make a copy for packing
        try:
            shutil.copy2(input_file, output_file)
        except Exception as e:
            return False, f"Failed to create output file: {str(e)}"
        
        # Run UPX
        try:
            cmd = [
                self.upx_path,
                f'-{compression_level}',  # Compression level
                '--best',                 # Use best compression
                '--lzma',                 # Use LZMA algorithm (if available)
                output_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Get file sizes for comparison
                original_size = os.path.getsize(input_file)
                packed_size = os.path.getsize(output_file)
                ratio = (1 - packed_size / original_size) * 100
                
                return True, (f"Successfully packed!\n"
                            f"Original: {original_size:,} bytes\n"
                            f"Packed: {packed_size:,} bytes\n"
                            f"Compression ratio: {ratio:.1f}%")
            else:
                return False, f"UPX error: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "UPX operation timed out (file too large?)"
        except Exception as e:
            return False, f"Error running UPX: {str(e)}"
    
    def unpack_binary(self, input_file: str, output_file: str = None) -> Tuple[bool, str]:
        """
        Unpack a UPX-packed binary.
        
        Args:
            input_file: Path to packed file
            output_file: Path to output file (optional)
            
        Returns:
            Tuple of (success, message)
        """
        if not self.is_upx_available():
            return False, "UPX is not installed. Install from: https://upx.github.io/"
        
        if not os.path.exists(input_file):
            return False, f"Input file not found: {input_file}"
        
        # Check if actually packed
        if not self.is_upx_packed(input_file):
            return False, "File does not appear to be UPX packed"
        
        # Prepare output file
        if output_file is None:
            output_file = input_file + ".unpacked"
        
        # Make a copy for unpacking
        try:
            shutil.copy2(input_file, output_file)
        except Exception as e:
            return False, f"Failed to create output file: {str(e)}"
        
        # Run UPX decompression
        try:
            cmd = [
                self.upx_path,
                '-d',  # Decompress
                output_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Get file sizes
                packed_size = os.path.getsize(input_file)
                unpacked_size = os.path.getsize(output_file)
                expansion = (unpacked_size / packed_size - 1) * 100
                
                return True, (f"Successfully unpacked!\n"
                            f"Packed: {packed_size:,} bytes\n"
                            f"Unpacked: {unpacked_size:,} bytes\n"
                            f"Expansion: {expansion:.1f}%")
            else:
                return False, f"UPX error: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "UPX operation timed out"
        except Exception as e:
            return False, f"Error running UPX: {str(e)}"
    
    def get_upx_info(self, file_path: str) -> Dict:
        """
        Get information about a UPX-packed file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with UPX information
        """
        if not self.is_upx_available():
            return {'error': 'UPX not available'}
        
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        try:
            cmd = [self.upx_path, '-l', file_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            info = {
                'is_packed': self.is_upx_packed(file_path),
                'file_size': os.path.getsize(file_path),
                'upx_version_used': 'Unknown'
            }
            
            if result.returncode == 0:
                # Parse UPX output for details
                info['upx_output'] = result.stdout
            
            return info
        
        except Exception as e:
            return {'error': str(e)}
    
    def get_installation_instructions(self) -> str:
        """
        Get UPX installation instructions for the current platform.
        
        Returns:
            Installation instructions string
        """
        import platform
        
        system = platform.system()
        
        if system == 'Linux':
            return (
                "UPX Installation (Linux):\n\n"
                "Ubuntu/Debian:\n"
                "  sudo apt-get update\n"
                "  sudo apt-get install upx-ucl\n\n"
                "Fedora/RHEL:\n"
                "  sudo dnf install upx\n\n"
                "Arch Linux:\n"
                "  sudo pacman -S upx\n\n"
                "Manual:\n"
                "  wget https://github.com/upx/upx/releases/latest\n"
                "  tar xvf upx-*.tar.xz\n"
                "  sudo mv upx-*/upx /usr/local/bin/"
            )
        
        elif system == 'Darwin':  # macOS
            return (
                "UPX Installation (macOS):\n\n"
                "Homebrew:\n"
                "  brew install upx\n\n"
                "Manual:\n"
                "  Download from https://github.com/upx/upx/releases\n"
                "  Extract and move to /usr/local/bin/"
            )
        
        elif system == 'Windows':
            return (
                "UPX Installation (Windows):\n\n"
                "1. Download from https://github.com/upx/upx/releases\n"
                "2. Extract upx.exe to C:\\upx\\ or C:\\Program Files\\upx\\\n"
                "3. Add to PATH environment variable\n\n"
                "Or use Chocolatey:\n"
                "  choco install upx"
            )
        
        else:
            return (
                "UPX Installation:\n\n"
                "Download from: https://github.com/upx/upx/releases\n"
                "Extract and add to system PATH"
            )
