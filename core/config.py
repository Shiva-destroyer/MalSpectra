"""
MalSpectra - Configuration Module
Manages application configuration and metadata
"""

import os
from pathlib import Path
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass
class MalSpectraConfig:
    """
    Configuration manager for MalSpectra framework.
    Stores paths, metadata, and application settings.
    """
    
    # Project Metadata
    PROJECT_NAME: str = "MalSpectra"
    VERSION: str = "1.0.0"
    DEVELOPER: str = "Sai Srujan Murthy"
    EMAIL: str = "saisrujanmurthy@gmail.com"
    LICENSE: str = "MIT"
    
    # Directory Paths
    ROOT_DIR: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    CORE_DIR: Path = field(init=False)
    MODULES_DIR: Path = field(init=False)
    LOGS_DIR: Path = field(init=False)
    DATA_DIR: Path = field(init=False)
    DOCS_DIR: Path = field(init=False)
    TESTS_DIR: Path = field(init=False)
    
    # Data Subdirectories
    SAMPLES_DIR: Path = field(init=False)
    OUTPUT_DIR: Path = field(init=False)
    
    # Log Configuration
    LOG_FILE: str = "malspectra.log"
    LOG_LEVEL: str = "DEBUG"
    
    # Module Configuration
    MODULES: list = field(default_factory=lambda: [
        "Reverse Engineering",
        "Ghidra Bridge",
        "Malware Sandbox",
        "Signature Generator",
        "API Hooking",
        "Code Injection",
        "Rootkit Analysis",
        "Botnet Analyzer",
        "Ransomware Helper",
        "Rootkit Analysis",
        "Botnet Analyzer",
        "Ransomware Decrypt",
        "Worm Simulator",
        "Trojan Detector",
        "Packer/Unpacker"
    ])
    
    MODULE_MAPPING: Dict[str, str] = field(default_factory=lambda: {
        "Reverse Engineering": "reverse_engineering",
        "Ghidra Bridge": "ghidra_bridge",
        "Malware Sandbox": "sandbox",
        "Signature Generator": "signature_gen",
        "API Hooking": "api_hooking",
        "Code Injection": "code_injection",
        "Rootkit Analysis": "rootkit_analysis",
        "Botnet Analyzer": "botnet_analyzer",
        "Ransomware Decrypt": "ransomware_decrypt",
        "Worm Simulator": "worm_sim",
        "Trojan Detector": "trojan_detect",
        "Packer/Unpacker": "packer_unpacker"
    })
    
    def __post_init__(self):
        """Initialize directory paths after instance creation."""
        self.CORE_DIR = self.ROOT_DIR / "core"
        self.MODULES_DIR = self.ROOT_DIR / "modules"
        self.LOGS_DIR = self.ROOT_DIR / "logs"
        self.DATA_DIR = self.ROOT_DIR / "data"
        self.DOCS_DIR = self.ROOT_DIR / "docs"
        self.TESTS_DIR = self.ROOT_DIR / "tests"
        
        # Data subdirectories
        self.SAMPLES_DIR = self.DATA_DIR / "samples"
        self.OUTPUT_DIR = self.DATA_DIR / "output"
        
        # Create directories if they don't exist
        self._create_directories()
    
    def _create_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        directories = [
            self.LOGS_DIR,
            self.DATA_DIR,
            self.SAMPLES_DIR,
            self.OUTPUT_DIR
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_module_path(self, module_name: str) -> Path:
        """
        Get the full path to a specific module.
        
        Args:
            module_name: Display name of the module
        
        Returns:
            Path to the module directory
        """
        module_folder = self.MODULE_MAPPING.get(module_name)
        if module_folder:
            return self.MODULES_DIR / module_folder
        raise ValueError(f"Module '{module_name}' not found in configuration")
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get configuration information as a dictionary.
        
        Returns:
            Dictionary containing configuration details
        """
        return {
            "project": self.PROJECT_NAME,
            "version": self.VERSION,
            "developer": self.DEVELOPER,
            "email": self.EMAIL,
            "license": self.LICENSE,
            "root_dir": str(self.ROOT_DIR),
            "modules_count": len(self.MODULES)
        }
    
    def __str__(self) -> str:
        """String representation of configuration."""
        return (
            f"{self.PROJECT_NAME} v{self.VERSION}\n"
            f"Developer: {self.DEVELOPER}\n"
            f"Email: {self.EMAIL}\n"
            f"License: {self.LICENSE}\n"
            f"Root Directory: {self.ROOT_DIR}\n"
            f"Modules: {len(self.MODULES)}"
        )


# Global configuration instance
config = MalSpectraConfig()


if __name__ == "__main__":
    # Test configuration
    print("=== MalSpectra Configuration ===")
    print(config)
    print("\n=== Available Modules ===")
    for idx, module in enumerate(config.MODULES, 1):
        print(f"{idx}. {module}")
    print("\n=== Directory Structure ===")
    print(f"Core: {config.CORE_DIR}")
    print(f"Modules: {config.MODULES_DIR}")
    print(f"Logs: {config.LOGS_DIR}")
    print(f"Data: {config.DATA_DIR}")
    print("\n[✓] Configuration test complete")
