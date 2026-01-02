"""
MalSpectra - Sandbox Execution Engine
Executes suspicious files in a monitored sandbox environment

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from .process_monitor import ProcessMonitor, ProcessInfo
from .file_monitor import FileMonitor, FileChange
from .network_monitor import NetworkMonitor, ConnectionInfo


class SandboxReport:
    """Container for sandbox execution results."""
    
    def __init__(self):
        self.target_file: str = ""
        self.execution_time: float = 0.0
        self.exit_code: Optional[int] = None
        self.timed_out: bool = False
        self.error_message: str = ""
        
        self.new_processes: list[ProcessInfo] = []
        self.terminated_processes: list[ProcessInfo] = []
        self.file_changes: list[FileChange] = []
        self.network_connections: list[ConnectionInfo] = []
        
        self.start_time: str = ""
        self.end_time: str = ""


class Sandbox:
    """
    Executes files in a monitored sandbox environment.
    Tracks process, file, and network activity.
    """
    
    def __init__(self, watch_dir: str = "./sandbox_watch"):
        """
        Initialize sandbox.
        
        Args:
            watch_dir: Directory to monitor for file changes
        """
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor(watch_dir)
        self.network_monitor = NetworkMonitor()
        self.watch_dir = Path(watch_dir)
    
    def execute(
        self,
        target_file: str,
        timeout: int = 10,
        args: list[str] = None
    ) -> SandboxReport:
        """
        Execute a file in the sandbox with monitoring.
        
        Args:
            target_file: Path to executable/script to run
            timeout: Execution timeout in seconds
            args: Command line arguments for the target
            
        Returns:
            SandboxReport with monitoring results
        """
        report = SandboxReport()
        report.target_file = target_file
        report.start_time = datetime.now().isoformat()
        
        target_path = Path(target_file)
        
        # Validate target exists
        if not target_path.exists():
            report.error_message = f"Target file not found: {target_file}"
            report.end_time = datetime.now().isoformat()
            return report
        
        # Start all monitors
        self.process_monitor.start_monitoring()
        self.file_monitor.start_monitoring()
        self.network_monitor.start_monitoring()
        
        # Build command
        if target_path.suffix == '.py':
            # Python script
            cmd = ['python3', str(target_path)]
        elif target_path.suffix in ['.sh', '.bash']:
            # Shell script
            cmd = ['bash', str(target_path)]
        else:
            # Assume it's an executable
            cmd = [str(target_path)]
        
        # Add arguments if provided
        if args:
            cmd.extend(args)
        
        # Execute target
        start_exec = time.time()
        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True,
                cwd=str(self.watch_dir)
            )
            report.exit_code = result.returncode
            
        except subprocess.TimeoutExpired:
            report.timed_out = True
            report.error_message = f"Execution timed out after {timeout} seconds"
        
        except FileNotFoundError:
            report.error_message = f"Failed to execute: Command not found"
        
        except Exception as e:
            report.error_message = f"Execution error: {str(e)}"
        
        end_exec = time.time()
        report.execution_time = end_exec - start_exec
        
        # Give system a moment to settle
        time.sleep(0.5)
        
        # Stop monitors and collect results
        report.new_processes = self.process_monitor.stop_monitoring()
        report.terminated_processes = self.process_monitor.get_terminated_processes()
        report.file_changes = self.file_monitor.stop_monitoring()
        report.network_connections = self.network_monitor.stop_monitoring()
        
        report.end_time = datetime.now().isoformat()
        return report
    
    def get_summary(self, report: SandboxReport) -> Dict[str, Any]:
        """
        Get summary statistics from a sandbox report.
        
        Args:
            report: Sandbox execution report
            
        Returns:
            Dictionary with summary stats
        """
        return {
            'target': report.target_file,
            'execution_time': f"{report.execution_time:.2f}s",
            'exit_code': report.exit_code,
            'timed_out': report.timed_out,
            'processes_created': len(report.new_processes),
            'processes_terminated': len(report.terminated_processes),
            'files_created': len([f for f in report.file_changes if f.change_type == 'created']),
            'files_modified': len([f for f in report.file_changes if f.change_type == 'modified']),
            'files_deleted': len([f for f in report.file_changes if f.change_type == 'deleted']),
            'network_connections': len(report.network_connections)
        }


if __name__ == "__main__":
    # Test sandbox with a simple script
    import tempfile
    
    # Create test script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("""
import time
import os

# Create a test file
with open('infected.txt', 'w') as f:
    f.write('Malware was here!')

print('Running malicious code...')
time.sleep(2)
print('Done!')
""")
        test_script = f.name
    
    print(f"Created test script: {test_script}")
    
    # Run in sandbox
    sandbox = Sandbox()
    print("\nExecuting in sandbox...")
    report = sandbox.execute(test_script, timeout=5)
    
    print("\n=== Sandbox Report ===")
    summary = sandbox.get_summary(report)
    for key, value in summary.items():
        print(f"{key}: {value}")
    
    # Cleanup
    import os
    os.unlink(test_script)
