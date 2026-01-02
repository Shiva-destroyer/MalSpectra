"""
MalSpectra - Ghidra Bridge
Executes headless Ghidra analysis

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from core.logger import get_logger
from .config_manager import GhidraConfigManager
from .script_gen import GhidraScriptGenerator


logger = get_logger("GhidraBridge")


class GhidraBridge:
    """
    Bridge to Ghidra headless analyzer for automated binary analysis.
    """
    
    def __init__(self):
        """Initialize Ghidra bridge."""
        self.config_manager = GhidraConfigManager()
        self.script_generator = GhidraScriptGenerator()
        self.temp_dir = None
    
    def is_configured(self) -> bool:
        """
        Check if Ghidra is configured.
        
        Returns:
            True if Ghidra path is set
        """
        return self.config_manager.is_configured()
    
    def configure(self, ghidra_path: str) -> bool:
        """
        Configure Ghidra headless path.
        
        Args:
            ghidra_path: Path to analyzeHeadless script
        
        Returns:
            True if configuration successful
        """
        return self.config_manager.set_ghidra_path(ghidra_path)
    
    def run_analysis(self, target_file: str, analysis_type: str = "functions") -> Optional[Dict[str, Any]]:
        """
        Run Ghidra headless analysis on target file.
        
        Args:
            target_file: Path to binary file to analyze
            analysis_type: Type of analysis ("functions" or "strings")
        
        Returns:
            Analysis results as dictionary or None on failure
        """
        if not self.is_configured():
            logger.error("Ghidra not configured")
            return None
        
        target_path = Path(target_file)
        if not target_path.exists():
            logger.error(f"Target file not found: {target_file}")
            return None
        
        # Create temporary project directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ghidra_project_"))
        project_name = "MalSpectra_Analysis"
        
        try:
            # Generate output JSON path
            output_json = self.temp_dir / "analysis_output.json"
            
            # Generate analysis script
            if analysis_type == "strings":
                script_path = self.script_generator.generate_strings_extraction_script(str(output_json))
            else:
                script_path = self.script_generator.generate_function_analysis_script(str(output_json))
            
            logger.info(f"Starting Ghidra analysis: {analysis_type}")
            logger.info(f"Target: {target_file}")
            
            # Build Ghidra command
            ghidra_headless = self.config_manager.get_ghidra_path()
            
            command = [
                ghidra_headless,
                str(self.temp_dir),
                project_name,
                "-import", str(target_path.absolute()),
                "-postScript", str(script_path.absolute()),
                "-deleteProject"  # Clean up after analysis
            ]
            
            logger.debug(f"Command: {' '.join(command)}")
            
            # Execute Ghidra
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            logger.debug(f"Ghidra exit code: {result.returncode}")
            
            if result.returncode != 0:
                logger.error(f"Ghidra analysis failed: {result.stderr}")
                return None
            
            # Read results
            if output_json.exists():
                with open(output_json, 'r') as f:
                    results = json.load(f)
                logger.info("Analysis completed successfully")
                return results
            else:
                logger.error("Output file not generated")
                return None
        
        except subprocess.TimeoutExpired:
            logger.error("Ghidra analysis timed out")
            return None
        
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}", exc_info=True)
            return None
        
        finally:
            # Cleanup temporary directory
            if self.temp_dir and self.temp_dir.exists():
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp dir: {str(e)}")
    
    def get_ghidra_path(self) -> Optional[str]:
        """
        Get configured Ghidra path.
        
        Returns:
            Ghidra headless path or None
        """
        return self.config_manager.get_ghidra_path()


if __name__ == "__main__":
    # Test bridge
    bridge = GhidraBridge()
    if bridge.is_configured():
        print(f"Ghidra configured at: {bridge.get_ghidra_path()}")
    else:
        print("Ghidra not configured")
