"""
Rootkit Detection Engine
Checks for hidden processes, LD_PRELOAD hooks, and promiscuous network interfaces

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
import psutil
import socket
import fcntl
import struct
from typing import List, Dict, Tuple
from pathlib import Path


class RootkitDetector:
    """Detects rootkit artifacts and hidden system components"""
    
    # Suspicious LD_PRELOAD indicators
    SUSPICIOUS_PRELOAD_PATTERNS = [
        'hook', 'inject', 'hide', 'stealth', 'rootkit',
        'backdoor', 'trojan', 'keylog', 'sniff'
    ]
    
    def __init__(self):
        """Initialize the rootkit detector"""
        self.findings = []
        
    def check_hidden_processes(self) -> Tuple[bool, List[Dict]]:
        """
        Compare PIDs from /proc with PIDs from psutil
        Hidden PIDs might indicate rootkit activity
        
        Returns:
            (is_clean, list_of_hidden_pids)
        """
        hidden_pids = []
        
        try:
            # Get PIDs from /proc directory
            proc_pids = set()
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_pids.add(int(entry))
            
            # Get PIDs from psutil
            psutil_pids = set(p.pid for p in psutil.process_iter(['pid']))
            
            # Find hidden PIDs (in /proc but not visible to psutil)
            hidden = proc_pids - psutil_pids
            
            for pid in hidden:
                try:
                    # Try to get process info from /proc
                    cmdline_path = f'/proc/{pid}/cmdline'
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, 'r') as f:
                            cmdline = f.read().replace('\x00', ' ').strip()
                        
                        hidden_pids.append({
                            'pid': pid,
                            'cmdline': cmdline or '<unknown>',
                            'threat_level': 'HIGH'
                        })
                except (PermissionError, FileNotFoundError):
                    # Process may have terminated or requires root
                    pass
            
            is_clean = len(hidden_pids) == 0
            return is_clean, hidden_pids
            
        except Exception as e:
            return False, [{'error': str(e)}]
    
    def check_ld_preload(self) -> Tuple[bool, List[Dict]]:
        """
        Check for LD_PRELOAD hooks in system and environment
        Malicious libraries can intercept system calls
        
        Returns:
            (is_clean, list_of_suspicious_preloads)
        """
        suspicious_preloads = []
        
        # Check /etc/ld.so.preload file
        preload_file = Path('/etc/ld.so.preload')
        if preload_file.exists():
            try:
                with open(preload_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        lines = content.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Check if suspicious
                                is_suspicious = any(
                                    pattern in line.lower() 
                                    for pattern in self.SUSPICIOUS_PRELOAD_PATTERNS
                                )
                                
                                suspicious_preloads.append({
                                    'location': '/etc/ld.so.preload',
                                    'library': line,
                                    'suspicious': is_suspicious,
                                    'threat_level': 'CRITICAL' if is_suspicious else 'MEDIUM'
                                })
            except PermissionError:
                suspicious_preloads.append({
                    'location': '/etc/ld.so.preload',
                    'error': 'Permission denied (requires root)',
                    'threat_level': 'UNKNOWN'
                })
        
        # Check LD_PRELOAD environment variable
        ld_preload_env = os.environ.get('LD_PRELOAD', '')
        if ld_preload_env:
            for lib in ld_preload_env.split(':'):
                lib = lib.strip()
                if lib:
                    is_suspicious = any(
                        pattern in lib.lower() 
                        for pattern in self.SUSPICIOUS_PRELOAD_PATTERNS
                    )
                    
                    suspicious_preloads.append({
                        'location': 'LD_PRELOAD environment',
                        'library': lib,
                        'suspicious': is_suspicious,
                        'threat_level': 'HIGH' if is_suspicious else 'LOW'
                    })
        
        # Check LD_LIBRARY_PATH for suspicious paths
        ld_library_path = os.environ.get('LD_LIBRARY_PATH', '')
        if ld_library_path:
            suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp']
            for path in ld_library_path.split(':'):
                path = path.strip()
                if any(susp in path for susp in suspicious_paths):
                    suspicious_preloads.append({
                        'location': 'LD_LIBRARY_PATH',
                        'library': path,
                        'suspicious': True,
                        'threat_level': 'MEDIUM',
                        'reason': 'Suspicious temporary directory in library path'
                    })
        
        is_clean = len([s for s in suspicious_preloads if s.get('suspicious', False)]) == 0
        return is_clean, suspicious_preloads
    
    def check_promiscuous_mode(self) -> Tuple[bool, List[Dict]]:
        """
        Check if network interfaces are in promiscuous mode
        Promiscuous mode allows packet sniffing
        
        Returns:
            (is_clean, list_of_promiscuous_interfaces)
        """
        promiscuous_interfaces = []
        
        try:
            # Get all network interfaces
            interfaces = psutil.net_if_stats()
            
            for iface_name, stats in interfaces.items():
                # Skip loopback
                if iface_name == 'lo':
                    continue
                
                try:
                    # Try to get interface flags using ioctl
                    # This requires socket operations
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                    # SIOCGIFFLAGS = 0x8913 (get interface flags)
                    flags = fcntl.ioctl(
                        sock.fileno(),
                        0x8913,  # SIOCGIFFLAGS
                        struct.pack('256s', iface_name[:15].encode('utf-8'))
                    )
                    flags_value = struct.unpack('H', flags[16:18])[0]
                    
                    # IFF_PROMISC = 0x100 (promiscuous mode flag)
                    is_promisc = bool(flags_value & 0x100)
                    
                    if is_promisc:
                        promiscuous_interfaces.append({
                            'interface': iface_name,
                            'status': 'PROMISCUOUS',
                            'threat_level': 'HIGH',
                            'description': 'Interface can capture all network traffic'
                        })
                    
                    sock.close()
                    
                except (OSError, PermissionError) as e:
                    # May require root privileges
                    if iface_name not in ['lo', 'docker0', 'virbr0']:
                        promiscuous_interfaces.append({
                            'interface': iface_name,
                            'status': 'UNKNOWN',
                            'threat_level': 'UNKNOWN',
                            'error': 'Requires root to check promiscuous mode'
                        })
        
        except Exception as e:
            return False, [{'error': f'Failed to check interfaces: {str(e)}'}]
        
        is_clean = len([i for i in promiscuous_interfaces if i.get('status') == 'PROMISCUOUS']) == 0
        return is_clean, promiscuous_interfaces
    
    def run_all_checks(self) -> Dict:
        """
        Run all rootkit detection checks
        
        Returns:
            Dictionary with all findings
        """
        results = {
            'hidden_processes': {},
            'ld_preload': {},
            'promiscuous_mode': {},
            'overall_status': 'CLEAN'
        }
        
        # Check hidden processes
        clean, findings = self.check_hidden_processes()
        results['hidden_processes'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        # Check LD_PRELOAD
        clean, findings = self.check_ld_preload()
        results['ld_preload'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        # Check promiscuous mode
        clean, findings = self.check_promiscuous_mode()
        results['promiscuous_mode'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        # Determine overall status
        if not results['hidden_processes']['clean']:
            results['overall_status'] = 'INFECTED'
        elif any(f.get('suspicious', False) for f in results['ld_preload']['findings']):
            results['overall_status'] = 'SUSPICIOUS'
        elif not results['promiscuous_mode']['clean']:
            results['overall_status'] = 'SUSPICIOUS'
        
        return results
