"""
Ransomware Identification Engine
Identifies ransomware families and verifies encryption

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
import math
from pathlib import Path
from typing import Tuple, Dict, Optional
from collections import Counter


class RansomwareIdentifier:
    """Identifies ransomware families based on file extensions and encryption patterns"""
    
    # Known ransomware extensions and their families
    RANSOMWARE_EXTENSIONS = {
        '.wannacry': {
            'family': 'WannaCry',
            'aka': ['WannaCrypt', 'Wana Decrypt0r'],
            'year': '2017',
            'severity': 'CRITICAL',
            'description': 'Exploits EternalBlue SMB vulnerability',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.locky': {
            'family': 'Locky',
            'aka': ['Locky Ransomware'],
            'year': '2016',
            'severity': 'HIGH',
            'description': 'Distributed via malicious email attachments',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.cerber': {
            'family': 'Cerber',
            'aka': ['Cerber Ransomware'],
            'year': '2016',
            'severity': 'HIGH',
            'description': 'Ransomware-as-a-Service (RaaS)',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.cryptolocker': {
            'family': 'CryptoLocker',
            'aka': ['Trojan.Cryptolocker'],
            'year': '2013',
            'severity': 'CRITICAL',
            'description': 'First major ransomware campaign',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.encrypted': {
            'family': 'Generic Ransomware',
            'aka': ['Various families'],
            'year': 'Various',
            'severity': 'HIGH',
            'description': 'Common extension used by multiple families',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.locked': {
            'family': 'Generic Ransomware',
            'aka': ['Various families'],
            'year': 'Various',
            'severity': 'HIGH',
            'description': 'Generic locked file extension',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.crypt': {
            'family': 'Generic Ransomware',
            'aka': ['Various families'],
            'year': 'Various',
            'severity': 'MEDIUM',
            'description': 'Generic crypt extension',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.crypto': {
            'family': 'TeslaCrypt',
            'aka': ['TeslaCrypt Ransomware'],
            'year': '2015',
            'severity': 'HIGH',
            'description': 'Targeted gamers, master key released',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html',
            'decryptor_available': True
        },
        '.petya': {
            'family': 'Petya/NotPetya',
            'aka': ['NotPetya', 'ExPetr'],
            'year': '2017',
            'severity': 'CRITICAL',
            'description': 'Disk-encrypting ransomware',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.ryuk': {
            'family': 'Ryuk',
            'aka': ['Ryuk Ransomware'],
            'year': '2018',
            'severity': 'CRITICAL',
            'description': 'Targeted ransomware for enterprises',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.maze': {
            'family': 'Maze',
            'aka': ['Maze Ransomware'],
            'year': '2019',
            'severity': 'CRITICAL',
            'description': 'Double extortion ransomware',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.revil': {
            'family': 'REvil/Sodinokibi',
            'aka': ['Sodinokibi', 'REvil'],
            'year': '2019',
            'severity': 'CRITICAL',
            'description': 'RaaS with double extortion',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.dharma': {
            'family': 'Dharma/Crysis',
            'aka': ['Crysis Ransomware'],
            'year': '2016',
            'severity': 'HIGH',
            'description': 'RaaS targeting organizations',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        },
        '.phobos': {
            'family': 'Phobos',
            'aka': ['Phobos Ransomware'],
            'year': '2019',
            'severity': 'HIGH',
            'description': 'Dharma variant',
            'nomoreransom': 'https://www.nomoreransom.org/en/decryption-tools.html'
        }
    }
    
    # High entropy threshold (typical for encrypted data)
    ENTROPY_THRESHOLD = 7.5
    
    def __init__(self):
        """Initialize ransomware identifier"""
        pass
    
    def identify_family(self, filename: str) -> Optional[Dict]:
        """
        Identify ransomware family based on file extension
        
        Args:
            filename: Name of the encrypted file
            
        Returns:
            Dictionary with family information or None
        """
        path = Path(filename)
        extension = path.suffix.lower()
        
        if extension in self.RANSOMWARE_EXTENSIONS:
            info = self.RANSOMWARE_EXTENSIONS[extension].copy()
            info['extension'] = extension
            info['confidence'] = 'HIGH'
            return info
        
        # Check for double extensions (e.g., file.txt.locky)
        if len(path.suffixes) >= 2:
            double_ext = ''.join(path.suffixes[-2:]).lower()
            for known_ext, info in self.RANSOMWARE_EXTENSIONS.items():
                if known_ext in double_ext:
                    result = info.copy()
                    result['extension'] = double_ext
                    result['confidence'] = 'MEDIUM'
                    return result
        
        # Check if extension contains known patterns
        for known_ext, info in self.RANSOMWARE_EXTENSIONS.items():
            if known_ext[1:] in extension:  # Remove leading dot
                result = info.copy()
                result['extension'] = extension
                result['confidence'] = 'LOW'
                result['note'] = 'Partial match, may be variant'
                return result
        
        return None
    
    def calculate_entropy(self, file_path: str, sample_size: int = 1024 * 100) -> float:
        """
        Calculate Shannon entropy of file
        High entropy (>7.5) indicates likely encrypted/compressed data
        
        Args:
            file_path: Path to file
            sample_size: Number of bytes to analyze (default 100KB)
            
        Returns:
            Entropy value (0-8)
        """
        try:
            with open(file_path, 'rb') as f:
                # Read sample
                data = f.read(sample_size)
                
                if len(data) == 0:
                    return 0.0
                
                # Count byte frequencies
                byte_counts = Counter(data)
                
                # Calculate entropy
                entropy = 0.0
                data_len = len(data)
                
                for count in byte_counts.values():
                    probability = count / data_len
                    if probability > 0:
                        entropy -= probability * math.log2(probability)
                
                return entropy
                
        except Exception as e:
            raise Exception(f"Failed to calculate entropy: {str(e)}")
    
    def verify_encryption(self, file_path: str) -> Tuple[bool, float, str]:
        """
        Verify if file is likely encrypted based on entropy
        
        Args:
            file_path: Path to file
            
        Returns:
            (is_encrypted, entropy_value, assessment)
        """
        entropy = self.calculate_entropy(file_path)
        
        if entropy >= self.ENTROPY_THRESHOLD:
            assessment = "HIGH - File is likely encrypted or compressed"
            is_encrypted = True
        elif entropy >= 7.0:
            assessment = "MEDIUM - File may be encrypted or contain binary data"
            is_encrypted = True
        elif entropy >= 6.0:
            assessment = "LOW - File appears to be normal binary data"
            is_encrypted = False
        else:
            assessment = "CLEAN - File is likely plain text or low-entropy data"
            is_encrypted = False
        
        return is_encrypted, entropy, assessment
    
    def get_file_info(self, file_path: str) -> Dict:
        """
        Get comprehensive file information
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with file information
        """
        path = Path(file_path)
        
        info = {
            'path': str(path),
            'name': path.name,
            'size': path.stat().st_size,
            'size_formatted': self._format_size(path.stat().st_size),
            'extension': path.suffix.lower()
        }
        
        return info
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Perform complete ransomware analysis on file
        
        Args:
            file_path: Path to suspected encrypted file
            
        Returns:
            Dictionary with complete analysis
        """
        results = {
            'file_info': {},
            'family_identification': None,
            'encryption_verification': {},
            'recommended_action': ''
        }
        
        # Get file info
        results['file_info'] = self.get_file_info(file_path)
        
        # Identify family
        family_info = self.identify_family(results['file_info']['name'])
        results['family_identification'] = family_info
        
        # Verify encryption
        is_encrypted, entropy, assessment = self.verify_encryption(file_path)
        results['encryption_verification'] = {
            'is_encrypted': is_encrypted,
            'entropy': round(entropy, 4),
            'assessment': assessment,
            'threshold': self.ENTROPY_THRESHOLD
        }
        
        # Generate recommendation
        if family_info and is_encrypted:
            results['recommended_action'] = 'SEEK_DECRYPTOR'
        elif family_info and not is_encrypted:
            results['recommended_action'] = 'FALSE_POSITIVE'
        elif not family_info and is_encrypted:
            results['recommended_action'] = 'UNKNOWN_FAMILY'
        else:
            results['recommended_action'] = 'NOT_RANSOMWARE'
        
        return results
