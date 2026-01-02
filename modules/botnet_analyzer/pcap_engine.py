"""
PCAP Analysis Engine
Detects botnet traffic patterns: DGA, suspicious ports, C2 beacons

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple
from pathlib import Path


class PCAPAnalyzer:
    """Analyzes PCAP files for botnet traffic indicators"""
    
    # Suspicious ports commonly used by malware
    SUSPICIOUS_PORTS = {
        6667: 'IRC (Botnet C2)',
        6666: 'IRC (Alternative)',
        4444: 'Metasploit/RAT',
        31337: 'BackOrifice',
        12345: 'NetBus',
        1234: 'SubSeven',
        9999: 'Generic RAT',
        8080: 'HTTP Proxy/C2',
        443: 'HTTPS (C2 over SSL)',
        53: 'DNS (Tunneling/DGA)'
    }
    
    # DGA detection threshold (queries per minute)
    DGA_THRESHOLD = 50
    
    # Beacon detection parameters
    BEACON_TIME_TOLERANCE = 2  # seconds
    BEACON_MIN_COUNT = 5  # minimum repetitions to flag
    
    def __init__(self):
        """Initialize PCAP analyzer"""
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is required for botnet analysis.\n"
                "Install with: pip install scapy"
            )
        
        self.packets = []
        self.total_packets = 0
        
    def load_pcap(self, file_path: str) -> bool:
        """
        Load PCAP file
        
        Args:
            file_path: Path to PCAP file
            
        Returns:
            True if successful
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"PCAP file not found: {file_path}")
            
            self.packets = rdpcap(str(path))
            self.total_packets = len(self.packets)
            return True
            
        except Exception as e:
            raise Exception(f"Failed to load PCAP: {str(e)}")
    
    def detect_high_frequency_dns(self) -> Tuple[bool, List[Dict]]:
        """
        Detect DGA (Domain Generation Algorithm) via high-frequency DNS queries
        
        Returns:
            (is_clean, list_of_suspicious_hosts)
        """
        if not self.packets:
            return True, []
        
        # Track DNS queries per source IP
        dns_queries = defaultdict(list)
        
        for packet in self.packets:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    timestamp = float(packet.time)
                    
                    dns_queries[src_ip].append({
                        'query': query_name,
                        'timestamp': timestamp
                    })
        
        # Analyze query frequency
        suspicious_hosts = []
        
        for src_ip, queries in dns_queries.items():
            if len(queries) < 10:  # Skip low-volume hosts
                continue
            
            # Sort by timestamp
            queries.sort(key=lambda x: x['timestamp'])
            
            # Calculate queries per minute
            if queries:
                time_span = queries[-1]['timestamp'] - queries[0]['timestamp']
                if time_span > 0:
                    queries_per_minute = (len(queries) / time_span) * 60
                    
                    if queries_per_minute > self.DGA_THRESHOLD:
                        # Extract unique domains
                        unique_domains = list(set(q['query'] for q in queries))
                        
                        suspicious_hosts.append({
                            'ip': src_ip,
                            'total_queries': len(queries),
                            'queries_per_minute': round(queries_per_minute, 2),
                            'time_span_seconds': round(time_span, 2),
                            'unique_domains': len(unique_domains),
                            'sample_domains': unique_domains[:5],
                            'threat_level': 'HIGH',
                            'indicator': 'Possible DGA activity'
                        })
        
        is_clean = len(suspicious_hosts) == 0
        return is_clean, suspicious_hosts
    
    def detect_suspicious_ports(self) -> Tuple[bool, List[Dict]]:
        """
        Detect traffic on known malware ports
        
        Returns:
            (is_clean, list_of_suspicious_connections)
        """
        if not self.packets:
            return True, []
        
        suspicious_connections = defaultdict(lambda: {
            'count': 0,
            'ports': set(),
            'descriptions': set()
        })
        
        for packet in self.packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check TCP
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                    if dst_port in self.SUSPICIOUS_PORTS:
                        key = f"{src_ip} -> {dst_ip}"
                        suspicious_connections[key]['count'] += 1
                        suspicious_connections[key]['ports'].add(dst_port)
                        suspicious_connections[key]['descriptions'].add(
                            self.SUSPICIOUS_PORTS[dst_port]
                        )
                
                # Check UDP
                if packet.haslayer(UDP):
                    dst_port = packet[UDP].dport
                    if dst_port in self.SUSPICIOUS_PORTS:
                        key = f"{src_ip} -> {dst_ip}"
                        suspicious_connections[key]['count'] += 1
                        suspicious_connections[key]['ports'].add(dst_port)
                        suspicious_connections[key]['descriptions'].add(
                            self.SUSPICIOUS_PORTS[dst_port]
                        )
        
        # Format results
        results = []
        for connection, data in suspicious_connections.items():
            src, dst = connection.split(' -> ')
            results.append({
                'source_ip': src,
                'destination_ip': dst,
                'packet_count': data['count'],
                'ports': sorted(list(data['ports'])),
                'port_descriptions': list(data['descriptions']),
                'threat_level': 'CRITICAL' if 31337 in data['ports'] or 4444 in data['ports'] else 'HIGH'
            })
        
        is_clean = len(results) == 0
        return is_clean, results
    
    def detect_beacons(self) -> Tuple[bool, List[Dict]]:
        """
        Detect periodic beaconing (regular connections to C2 server)
        
        Returns:
            (is_clean, list_of_beacons)
        """
        if not self.packets:
            return True, []
        
        # Track connection timestamps per IP pair
        connections = defaultdict(list)
        
        for packet in self.packets:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                timestamp = float(packet.time)
                
                # Track outbound connections
                key = f"{src_ip}->{dst_ip}"
                connections[key].append(timestamp)
        
        # Analyze for periodic patterns
        beacons = []
        
        for connection, timestamps in connections.items():
            if len(timestamps) < self.BEACON_MIN_COUNT:
                continue
            
            # Sort timestamps
            timestamps.sort()
            
            # Calculate time differences between consecutive connections
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if not intervals:
                continue
            
            # Check for consistent intervals (beaconing)
            avg_interval = sum(intervals) / len(intervals)
            
            # Calculate variance
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # If standard deviation is low relative to average, it's likely a beacon
            if avg_interval > 10 and std_dev < self.BEACON_TIME_TOLERANCE:
                src, dst = connection.split('->')
                
                beacons.append({
                    'source_ip': src,
                    'destination_ip': dst,
                    'connection_count': len(timestamps),
                    'avg_interval_seconds': round(avg_interval, 2),
                    'std_deviation': round(std_dev, 2),
                    'total_duration_seconds': round(timestamps[-1] - timestamps[0], 2),
                    'threat_level': 'HIGH',
                    'indicator': 'Periodic C2 beacon detected'
                })
        
        is_clean = len(beacons) == 0
        return is_clean, beacons
    
    def analyze_pcap(self, file_path: str) -> Dict:
        """
        Perform complete PCAP analysis
        
        Args:
            file_path: Path to PCAP file
            
        Returns:
            Dictionary with all findings
        """
        # Load PCAP
        self.load_pcap(file_path)
        
        results = {
            'file_path': file_path,
            'total_packets': self.total_packets,
            'dga_detection': {},
            'suspicious_ports': {},
            'beacon_detection': {},
            'overall_threat': 'CLEAN'
        }
        
        # Run detections
        clean, findings = self.detect_high_frequency_dns()
        results['dga_detection'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        clean, findings = self.detect_suspicious_ports()
        results['suspicious_ports'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        clean, findings = self.detect_beacons()
        results['beacon_detection'] = {
            'clean': clean,
            'findings': findings,
            'count': len(findings)
        }
        
        # Determine overall threat
        if not results['dga_detection']['clean']:
            results['overall_threat'] = 'CRITICAL'
        elif not results['suspicious_ports']['clean']:
            critical_ports = any(
                f.get('threat_level') == 'CRITICAL' 
                for f in results['suspicious_ports']['findings']
            )
            results['overall_threat'] = 'CRITICAL' if critical_ports else 'HIGH'
        elif not results['beacon_detection']['clean']:
            results['overall_threat'] = 'HIGH'
        
        return results
