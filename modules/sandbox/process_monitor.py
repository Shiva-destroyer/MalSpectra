"""
MalSpectra - Process Monitor
Monitors process creation and termination

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import psutil
from typing import Dict, List, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProcessInfo:
    """Information about a process."""
    pid: int
    name: str
    cmdline: str
    create_time: float
    username: str
    

class ProcessMonitor:
    """
    Monitors system processes to detect new process creation.
    Useful for identifying malware spawning child processes.
    """
    
    def __init__(self):
        """Initialize process monitor."""
        self.baseline_pids: Set[int] = set()
        self.baseline_processes: Dict[int, ProcessInfo] = {}
        self.monitoring = False
    
    def start_monitoring(self) -> int:
        """
        Take a baseline snapshot of running processes.
        
        Returns:
            Number of processes in baseline
        """
        self.baseline_pids.clear()
        self.baseline_processes.clear()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                
                self.baseline_pids.add(pid)
                self.baseline_processes[pid] = ProcessInfo(
                    pid=pid,
                    name=info['name'] or 'Unknown',
                    cmdline=' '.join(info['cmdline']) if info['cmdline'] else '',
                    create_time=info['create_time'],
                    username=info['username'] or 'Unknown'
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.monitoring = True
        return len(self.baseline_pids)
    
    def stop_monitoring(self) -> List[ProcessInfo]:
        """
        Compare current processes to baseline and identify new processes.
        
        Returns:
            List of new processes created since baseline
        """
        if not self.monitoring:
            return []
        
        new_processes = []
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                
                # Check if this is a new process
                if pid not in self.baseline_pids:
                    new_processes.append(ProcessInfo(
                        pid=pid,
                        name=info['name'] or 'Unknown',
                        cmdline=' '.join(info['cmdline']) if info['cmdline'] else '',
                        create_time=info['create_time'],
                        username=info['username'] or 'Unknown'
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.monitoring = False
        return new_processes
    
    def get_terminated_processes(self) -> List[ProcessInfo]:
        """
        Identify processes that were terminated since baseline.
        
        Returns:
            List of processes that no longer exist
        """
        if not self.monitoring:
            return []
        
        current_pids = {proc.info['pid'] for proc in psutil.process_iter(['pid'])}
        terminated = []
        
        for pid, proc_info in self.baseline_processes.items():
            if pid not in current_pids:
                terminated.append(proc_info)
        
        return terminated
    
    def get_baseline_count(self) -> int:
        """
        Get the number of processes in baseline.
        
        Returns:
            Process count
        """
        return len(self.baseline_pids)


if __name__ == "__main__":
    # Test process monitor
    monitor = ProcessMonitor()
    print(f"Baseline: {monitor.start_monitoring()} processes")
    
    import time
    print("Waiting 5 seconds...")
    time.sleep(5)
    
    new_procs = monitor.stop_monitoring()
    print(f"New processes: {len(new_procs)}")
    for proc in new_procs:
        print(f"  - {proc.name} (PID: {proc.pid})")
