"""
MalSpectra - File Monitor
Monitors file system changes in a directory

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FileChange:
    """Information about a file change."""
    path: str
    change_type: str  # 'created', 'modified', 'deleted'
    timestamp: str
    size: int = 0


class FileMonitor:
    """
    Monitors a directory for file system changes.
    Uses simple snapshot comparison approach.
    """
    
    def __init__(self, watch_dir: str):
        """
        Initialize file monitor.
        
        Args:
            watch_dir: Directory to monitor
        """
        self.watch_dir = Path(watch_dir)
        self.baseline_files: Dict[str, float] = {}  # path -> mtime
        self.monitoring = False
    
    def start_monitoring(self) -> int:
        """
        Take baseline snapshot of directory.
        
        Returns:
            Number of files in baseline
        """
        self.baseline_files.clear()
        
        if not self.watch_dir.exists():
            self.watch_dir.mkdir(parents=True, exist_ok=True)
        
        for root, dirs, files in os.walk(self.watch_dir):
            for file in files:
                file_path = Path(root) / file
                try:
                    stat = file_path.stat()
                    self.baseline_files[str(file_path)] = stat.st_mtime
                except (OSError, PermissionError):
                    continue
        
        self.monitoring = True
        return len(self.baseline_files)
    
    def stop_monitoring(self) -> List[FileChange]:
        """
        Compare current state to baseline and identify changes.
        
        Returns:
            List of file changes detected
        """
        if not self.monitoring:
            return []
        
        changes = []
        current_files: Dict[str, float] = {}
        
        # Scan current state
        for root, dirs, files in os.walk(self.watch_dir):
            for file in files:
                file_path = Path(root) / file
                try:
                    stat = file_path.stat()
                    current_files[str(file_path)] = stat.st_mtime
                    
                    # Check if new file
                    if str(file_path) not in self.baseline_files:
                        changes.append(FileChange(
                            path=str(file_path.relative_to(self.watch_dir)),
                            change_type='created',
                            timestamp=datetime.now().isoformat(),
                            size=stat.st_size
                        ))
                    # Check if modified
                    elif stat.st_mtime > self.baseline_files[str(file_path)]:
                        changes.append(FileChange(
                            path=str(file_path.relative_to(self.watch_dir)),
                            change_type='modified',
                            timestamp=datetime.now().isoformat(),
                            size=stat.st_size
                        ))
                except (OSError, PermissionError):
                    continue
        
        # Check for deleted files
        for file_path in self.baseline_files.keys():
            if file_path not in current_files:
                try:
                    rel_path = Path(file_path).relative_to(self.watch_dir)
                    changes.append(FileChange(
                        path=str(rel_path),
                        change_type='deleted',
                        timestamp=datetime.now().isoformat(),
                        size=0
                    ))
                except ValueError:
                    continue
        
        self.monitoring = False
        return changes
    
    def get_watch_directory(self) -> Path:
        """
        Get the monitored directory.
        
        Returns:
            Path to watch directory
        """
        return self.watch_dir


if __name__ == "__main__":
    # Test file monitor
    import tempfile
    import time
    
    with tempfile.TemporaryDirectory() as tmpdir:
        monitor = FileMonitor(tmpdir)
        print(f"Monitoring: {tmpdir}")
        print(f"Baseline: {monitor.start_monitoring()} files")
        
        # Create a test file
        test_file = Path(tmpdir) / "test.txt"
        test_file.write_text("Hello, World!")
        
        time.sleep(1)
        
        changes = monitor.stop_monitoring()
        print(f"\nChanges detected: {len(changes)}")
        for change in changes:
            print(f"  - {change.change_type.upper()}: {change.path}")
