"""
MalSpectra - Ghidra Bridge Configuration Manager
Manages Ghidra headless analyzer path configuration

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import json
from pathlib import Path
from typing import Optional


class GhidraConfigManager:
    """
    Manages configuration for Ghidra headless analyzer.
    Stores and retrieves Ghidra installation path.
    """
    
    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize config manager.
        
        Args:
            config_file: Path to config file (default: core config dir)
        """
        if config_file is None:
            config_dir = Path(__file__).parent.parent.parent / "core"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "ghidra_config.json"
        
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except IOError as e:
            raise IOError(f"Failed to save configuration: {str(e)}")
    
    def set_ghidra_path(self, path: str) -> bool:
        """
        Set Ghidra headless analyzer path.
        
        Args:
            path: Path to analyzeHeadless script
        
        Returns:
            True if path is valid and saved
        """
        ghidra_path = Path(path)
        
        # Validate path exists
        if not ghidra_path.exists():
            return False
        
        # Store absolute path
        self.config['ghidra_headless_path'] = str(ghidra_path.absolute())
        self._save_config()
        return True
    
    def get_ghidra_path(self) -> Optional[str]:
        """
        Get configured Ghidra headless path.
        
        Returns:
            Path string or None if not configured
        """
        return self.config.get('ghidra_headless_path')
    
    def is_configured(self) -> bool:
        """
        Check if Ghidra path is configured.
        
        Returns:
            True if configured
        """
        path = self.get_ghidra_path()
        if path is None:
            return False
        
        # Verify path still exists
        return Path(path).exists()
    
    def clear_config(self) -> None:
        """Clear all configuration."""
        self.config = {}
        self._save_config()
    
    def get_all_settings(self) -> dict:
        """
        Get all configuration settings.
        
        Returns:
            Configuration dictionary
        """
        return self.config.copy()


if __name__ == "__main__":
    # Test configuration manager
    manager = GhidraConfigManager()
    
    if manager.is_configured():
        print(f"Ghidra Path: {manager.get_ghidra_path()}")
    else:
        print("Ghidra not configured")
