"""
MalSpectra - Network Monitor
Monitors network connections made by processes

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import psutil
from typing import List, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: int
    process_name: str


class NetworkMonitor:
    """
    Monitors network connections on the system.
    Tracks new connections established after monitoring starts.
    """
    
    def __init__(self):
        """Initialize network monitor."""
        self.baseline_connections: Set[tuple] = set()
        self.monitoring = False
    
    def _get_connection_key(self, conn) -> tuple:
        """
        Create unique key for a connection.
        
        Args:
            conn: psutil connection object
            
        Returns:
            Tuple representing connection
        """
        try:
            return (
                conn.laddr.ip if conn.laddr else None,
                conn.laddr.port if conn.laddr else None,
                conn.raddr.ip if conn.raddr else None,
                conn.raddr.port if conn.raddr else None,
                conn.status,
                conn.pid
            )
        except AttributeError:
            return (None, None, None, None, None, conn.pid)
    
    def start_monitoring(self) -> int:
        """
        Take baseline snapshot of network connections.
        
        Returns:
            Number of baseline connections
        """
        self.baseline_connections.clear()
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                key = self._get_connection_key(conn)
                self.baseline_connections.add(key)
        except (psutil.AccessDenied, PermissionError):
            # May need elevated privileges
            pass
        
        self.monitoring = True
        return len(self.baseline_connections)
    
    def stop_monitoring(self) -> List[ConnectionInfo]:
        """
        Compare current connections to baseline.
        
        Returns:
            List of new connections established
        """
        if not self.monitoring:
            return []
        
        new_connections = []
        
        try:
            current_connections = psutil.net_connections(kind='inet')
            
            for conn in current_connections:
                key = self._get_connection_key(conn)
                
                # Check if this is a new connection
                if key not in self.baseline_connections:
                    # Get process name
                    process_name = "Unknown"
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # Create connection info
                    local_addr = conn.laddr.ip if conn.laddr else "N/A"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_addr = conn.raddr.ip if conn.raddr else "N/A"
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    new_connections.append(ConnectionInfo(
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        status=conn.status,
                        pid=conn.pid if conn.pid else 0,
                        process_name=process_name
                    ))
        except (psutil.AccessDenied, PermissionError):
            pass
        
        self.monitoring = False
        return new_connections


if __name__ == "__main__":
    # Test network monitor
    import time
    
    monitor = NetworkMonitor()
    baseline_count = monitor.start_monitoring()
    print(f"Baseline connections: {baseline_count}")
    
    print("Monitoring for 5 seconds...")
    print("Try opening a browser or making a network request...")
    time.sleep(5)
    
    new_conns = monitor.stop_monitoring()
    print(f"\nNew connections detected: {len(new_conns)}")
    for conn in new_conns[:10]:  # Show first 10
        print(f"  - {conn.process_name} (PID: {conn.pid})")
        print(f"    {conn.local_address}:{conn.local_port} -> {conn.remote_address}:{conn.remote_port}")
        print(f"    Status: {conn.status}")
