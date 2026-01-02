"""
MalSpectra - Trojan Detection Heuristics Engine
Implements behavioral heuristics for RAT detection

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import re
import struct
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict


class HeuristicScanner:
    """
    Heuristic-based scanner for detecting trojan behaviors.
    Uses pattern matching and behavioral analysis.
    """
    
    # Suspicious API combinations for different RAT behaviors
    SUSPICIOUS_API_PATTERNS = {
        'keylogger': {
            'apis': ['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx', 
                    'GetKeyState', 'ToUnicodeEx'],
            'score': 35,
            'description': 'Keylogging capability detected'
        },
        'remote_access': {
            'apis': ['WinExec', 'CreateProcess', 'ShellExecute', 'system', 'exec'],
            'score': 30,
            'description': 'Remote command execution capability'
        },
        'network_communication': {
            'apis': ['InternetOpen', 'InternetConnect', 'HttpSendRequest', 
                    'socket', 'connect', 'send', 'recv', 'WSAStartup'],
            'score': 20,
            'description': 'Network communication detected'
        },
        'persistence': {
            'apis': ['RegCreateKey', 'RegSetValue', 'RegOpenKey', 
                    'CreateService', 'OpenSCManager'],
            'score': 25,
            'description': 'Persistence mechanism detected'
        },
        'screen_capture': {
            'apis': ['BitBlt', 'GetDC', 'CreateCompatibleBitmap', 
                    'GetDIBits', 'StretchBlt'],
            'score': 30,
            'description': 'Screen capture capability'
        },
        'file_operations': {
            'apis': ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 
                    'CopyFile', 'MoveFile'],
            'score': 15,
            'description': 'File manipulation capability'
        },
        'anti_analysis': {
            'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
                    'NtQueryInformationProcess', 'OutputDebugString'],
            'score': 40,
            'description': 'Anti-debugging/analysis techniques'
        }
    }
    
    def __init__(self, file_path: str):
        """
        Initialize scanner with target file.
        
        Args:
            file_path: Path to file to scan
        """
        self.file_path = Path(file_path)
        self.suspicion_score = 0
        self.findings = defaultdict(list)
        self.detected_behaviors = []
    
    def scan_imports(self, pe_data: bytes = None) -> Tuple[int, List[Dict]]:
        """
        Scan PE imports for suspicious API combinations.
        
        Args:
            pe_data: PE file data (optional, will read from file if None)
            
        Returns:
            Tuple of (score, list of findings)
        """
        if pe_data is None:
            try:
                with open(self.file_path, 'rb') as f:
                    pe_data = f.read()
            except Exception as e:
                return 0, [{'error': f'Failed to read file: {str(e)}'}]
        
        findings = []
        score = 0
        
        # Convert to string for pattern matching
        try:
            pe_text = pe_data.decode('latin-1')
        except:
            pe_text = str(pe_data)
        
        # Check each behavior pattern
        for behavior, pattern_info in self.SUSPICIOUS_API_PATTERNS.items():
            detected_apis = []
            
            for api in pattern_info['apis']:
                # Case-insensitive search for API names
                if re.search(rf'\b{re.escape(api)}\b', pe_text, re.IGNORECASE):
                    detected_apis.append(api)
            
            # If multiple APIs from same category detected, flag it
            if len(detected_apis) >= 2:
                score += pattern_info['score']
                findings.append({
                    'behavior': behavior,
                    'description': pattern_info['description'],
                    'detected_apis': detected_apis,
                    'score': pattern_info['score'],
                    'severity': self._get_severity(pattern_info['score'])
                })
        
        return score, findings
    
    def scan_strings(self) -> Tuple[int, List[Dict]]:
        """
        Scan file strings for suspicious indicators.
        
        Returns:
            Tuple of (score, list of findings)
        """
        suspicious_patterns = {
            'reverse_shell': {
                'patterns': [
                    r'cmd\.exe\s+/c',
                    r'powershell\s+-nop',
                    r'powershell\s+-w\s+hidden',
                    r'powershell\s+-enc',
                    r'/bin/sh\s+-i',
                    r'/bin/bash\s+-i',
                    r'nc\s+-[e|c]',
                    r'netcat'
                ],
                'score': 45,
                'description': 'Reverse shell indicators'
            },
            'c2_communication': {
                'patterns': [
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}',  # IP:Port
                    r'https?://[a-zA-Z0-9\-\.]+/[a-zA-Z0-9\-_/]+',  # Suspicious URLs
                    r'POST\s+/[a-z]+\s+HTTP',
                    r'User-Agent:\s*[^\\n]+bot',
                ],
                'score': 35,
                'description': 'C2 communication patterns'
            },
            'credential_theft': {
                'patterns': [
                    r'password',
                    r'passwd',
                    r'credential',
                    r'login',
                    r'username',
                    r'admin',
                    r'root'
                ],
                'score': 20,
                'description': 'Credential harvesting keywords'
            },
            'persistence_indicators': {
                'patterns': [
                    r'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
                    r'HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
                    r'\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu',
                    r'schtasks',
                    r'/create\s+/tn',
                ],
                'score': 30,
                'description': 'Persistence mechanism strings'
            },
            'data_exfiltration': {
                'patterns': [
                    r'upload',
                    r'exfil',
                    r'send.*file',
                    r'PUT\s+/',
                    r'multipart/form-data'
                ],
                'score': 25,
                'description': 'Data exfiltration indicators'
            }
        }
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            # Extract printable strings
            strings = self._extract_strings(content)
            
        except Exception as e:
            return 0, [{'error': f'Failed to read file: {str(e)}'}]
        
        findings = []
        score = 0
        
        for category, pattern_info in suspicious_patterns.items():
            matches = []
            
            for pattern in pattern_info['patterns']:
                for string in strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        matches.append(string[:100])  # Limit string length
            
            # Remove duplicates
            matches = list(set(matches))
            
            if matches:
                # Scale score based on number of matches
                match_score = min(pattern_info['score'], 
                                pattern_info['score'] * (len(matches) // 2 + 1))
                score += match_score
                
                findings.append({
                    'category': category,
                    'description': pattern_info['description'],
                    'matches': matches[:5],  # Limit to 5 examples
                    'match_count': len(matches),
                    'score': match_score,
                    'severity': self._get_severity(match_score)
                })
        
        return score, findings
    
    def scan_entropy(self) -> Tuple[int, Dict]:
        """
        Analyze file sections for high entropy (possible encryption/packing).
        
        Returns:
            Tuple of (score, findings dict)
        """
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            return 0, {'error': f'Failed to read file: {str(e)}'}
        
        # Calculate Shannon entropy
        if len(content) == 0:
            return 0, {'entropy': 0.0, 'assessment': 'Empty file'}
        
        from collections import Counter
        import math
        
        byte_counts = Counter(content)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / len(content)
            entropy -= probability * math.log2(probability)
        
        # High entropy suggests encryption/packing
        score = 0
        assessment = ""
        
        if entropy >= 7.5:
            score = 35
            assessment = "Very high entropy - likely packed/encrypted"
        elif entropy >= 7.0:
            score = 25
            assessment = "High entropy - possibly packed"
        elif entropy >= 6.5:
            score = 15
            assessment = "Moderately high entropy"
        else:
            assessment = "Normal entropy"
        
        return score, {
            'entropy': entropy,
            'assessment': assessment,
            'score': score
        }
    
    def scan_pe_characteristics(self) -> Tuple[int, List[Dict]]:
        """
        Analyze PE file characteristics for suspicious attributes.
        
        Returns:
            Tuple of (score, list of findings)
        """
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
        except:
            return 0, [{'error': 'Failed to read file'}]
        
        # Check if PE file
        if len(data) < 64 or data[:2] != b'MZ':
            return 0, [{'info': 'Not a PE file'}]
        
        findings = []
        score = 0
        
        try:
            # Parse DOS header
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            
            if e_lfanew >= len(data) - 4:
                return 0, [{'error': 'Invalid PE structure'}]
            
            # Check PE signature
            if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return 0, [{'error': 'Invalid PE signature'}]
            
            # Parse COFF header (20 bytes after PE signature)
            coff_offset = e_lfanew + 4
            characteristics = struct.unpack('<H', data[coff_offset+18:coff_offset+20])[0]
            
            # Check suspicious characteristics
            suspicious_flags = {
                0x2000: ('DLL file', 15, 'Potentially malicious DLL'),
                0x0002: ('Executable', 0, 'Standard executable'),
                0x0020: ('Large address aware', 5, 'Can access >2GB memory'),
            }
            
            for flag, (name, flag_score, desc) in suspicious_flags.items():
                if characteristics & flag:
                    if flag_score > 0:
                        score += flag_score
                    findings.append({
                        'characteristic': name,
                        'description': desc,
                        'score': flag_score
                    })
            
        except Exception as e:
            return 0, [{'error': f'PE parsing error: {str(e)}'}]
        
        return score, findings
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """
        Extract printable ASCII strings from binary data.
        
        Args:
            data: Binary data
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        strings = []
        current_string = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        
        # Don't forget last string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
        
        return strings
    
    def _get_severity(self, score: int) -> str:
        """Map score to severity level."""
        if score >= 40:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def perform_full_scan(self) -> Dict:
        """
        Perform comprehensive heuristic scan.
        
        Returns:
            Dictionary with all findings and total score
        """
        results = {
            'file_path': str(self.file_path),
            'file_size': os.path.getsize(self.file_path) if os.path.exists(self.file_path) else 0,
            'total_score': 0,
            'assessment': '',
            'import_findings': [],
            'string_findings': [],
            'entropy_findings': {},
            'pe_findings': []
        }
        
        # Run all scans
        import_score, import_findings = self.scan_imports()
        string_score, string_findings = self.scan_strings()
        entropy_score, entropy_findings = self.scan_entropy()
        pe_score, pe_findings = self.scan_pe_characteristics()
        
        # Aggregate results
        results['import_findings'] = import_findings
        results['string_findings'] = string_findings
        results['entropy_findings'] = entropy_findings
        results['pe_findings'] = pe_findings
        
        # Calculate total score (capped at 100)
        total_score = min(100, import_score + string_score + entropy_score + pe_score)
        results['total_score'] = total_score
        
        # Determine assessment
        if total_score >= 80:
            results['assessment'] = "HIGHLY SUSPICIOUS - Likely Trojan/RAT"
            results['threat_level'] = "CRITICAL"
        elif total_score >= 60:
            results['assessment'] = "SUSPICIOUS - Possible Trojan Activity"
            results['threat_level'] = "HIGH"
        elif total_score >= 40:
            results['assessment'] = "MODERATE RISK - Further Investigation Recommended"
            results['threat_level'] = "MEDIUM"
        elif total_score >= 20:
            results['assessment'] = "LOW RISK - Some Suspicious Indicators"
            results['threat_level'] = "LOW"
        else:
            results['assessment'] = "CLEAN - No Significant Threats Detected"
            results['threat_level'] = "SAFE"
        
        return results
