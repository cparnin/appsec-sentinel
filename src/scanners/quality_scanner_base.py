"""
Base class for code quality scanners with bundled config support.

This provides a common framework for all quality linters (ESLint, Pylint, Checkstyle, etc.)
to avoid code duplication and ensure consistent behavior.

Architecture:
1. Check if linter is installed
2. Check if repo has config
3. Fallback to AppSec-Sentinel bundled config if needed
4. Run scan with standardized output
5. Normalize findings to AppSec-Sentinel format
"""

import subprocess
import json
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple
from logging_config import get_logger

logger = get_logger(__name__)


class QualityScannerBase(ABC):
    """
    Base class for code quality scanners.

    Each linter implements this to get:
    - Automatic bundled config support
    - Consistent error handling
    - Standardized output format
    - Installation checking
    """

    def __init__(self):
        self.logger = logger
        self.appsec_root = Path(__file__).parent.parent.parent
        self.configs_dir = self.appsec_root / "configs"

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Tool name (e.g., 'eslint', 'pylint', 'checkstyle')"""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Display name for output (e.g., 'ESLint', 'Pylint')"""
        pass

    @property
    @abstractmethod
    def check_command(self) -> List[str]:
        """Command to check if tool is installed (e.g., ['eslint', '--version'])"""
        pass

    @property
    @abstractmethod
    def languages(self) -> List[str]:
        """Languages this scanner supports (e.g., ['javascript', 'typescript'])"""
        pass

    @abstractmethod
    def get_repo_config_paths(self, repo_path: Path) -> List[Path]:
        """
        Return list of possible config file paths in repo.

        Example for ESLint:
        return [
            repo_path / ".eslintrc.json",
            repo_path / ".eslintrc.js",
            repo_path / "eslint.config.js"
        ]
        """
        pass

    @abstractmethod
    def get_bundled_config_path(self, repo_path: Path) -> Optional[Path]:
        """
        Return path to AppSec-Sentinel bundled config file.

        Can detect tool version and return appropriate config.
        Return None if no bundled config available.
        """
        pass

    @abstractmethod
    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Optional[Path]) -> List[str]:
        """
        Build the command to run the scanner.

        Args:
            repo_path: Repository being scanned
            output_file: Where to write JSON output
            config_path: Config file to use (None = tool's default)

        Returns:
            Command as list of strings
        """
        pass

    @abstractmethod
    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> Dict:
        """
        Convert tool's output format to AppSec-Sentinel standard format.

        Standard format:
        {
            'tool': 'eslint',
            'category': 'code_quality',
            'severity': 'medium',  # low/medium/high
            'check_id': 'no-unused-vars',
            'path': 'app.js',
            'start': {'line': 10, 'col': 5},
            'end': {'line': 10, 'col': 15},
            'extra': {
                'message': 'Variable is unused',
                'metadata': {...}
            }
        }
        """
        pass

    def check_installed(self) -> bool:
        """Check if the tool is installed and accessible."""
        try:
            result = subprocess.run(
                self.check_command,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                self.logger.debug(f"{self.display_name} found: {version}")
                return True
            return False
        except FileNotFoundError:
            self.logger.debug(f"{self.display_name} not found in PATH")
            return False
        except Exception as e:
            self.logger.debug(f"Error checking {self.display_name} installation: {e}")
            return False

    def find_config(self, repo_path: Path) -> Optional[Path]:
        """
        Find config file: repo config > bundled config > None.

        Returns:
            Path to config file, or None if tool should use defaults
        """
        # Check if repo has its own config
        for config_path in self.get_repo_config_paths(repo_path):
            if config_path.exists():
                self.logger.debug(f"Using repo config: {config_path}")
                return config_path

        # Use bundled config as fallback
        bundled_config = self.get_bundled_config_path(repo_path)
        if bundled_config and bundled_config.exists():
            self.logger.info(f"📋 No {self.display_name} config in repo - using AppSec-Sentinel default config")
            return bundled_config

        # No config available
        self.logger.debug(f"No config found for {self.display_name}, tool will use defaults")
        return None

    def get_scan_env(self, config_path: Optional[Path]) -> Dict[str, str]:
        """
        Get environment variables for the scan.
        Override this if tool needs specific env vars based on config.
        """
        return os.environ.copy()

    def run_scan(self, repo_path: str, output_dir: str = None) -> List[Dict]:
        """
        Main entry point - runs the quality scan.

        This method orchestrates the entire scan process:
        1. Check installation
        2. Find/use config
        3. Run scanner
        4. Parse results
        5. Normalize findings

        Returns:
            List of normalized findings
        """
        try:
            import os
            
            # Check if tool is installed
            if not self.check_installed():
                # Print to stdout so users see it (not just logs)
                print(f"⚠️  {self.display_name} not installed - skipping {'/'.join(self.languages)} code quality scan")
                self.logger.info(f"💡 Install {self.display_name} to enable code quality scanning")
                return []

            # Set up paths
            if output_dir is None:
                from config import BASE_OUTPUT_DIR
                output_path = Path(BASE_OUTPUT_DIR) / "raw"
            else:
                output_path = Path(output_dir)

            output_path = output_path.resolve()

            output_path.mkdir(parents=True, exist_ok=True)
            output_file = output_path / f"{self.tool_name}.json"

            repo_path_obj = Path(repo_path).resolve()
            if not repo_path_obj.exists():
                self.logger.error(f"Repository path does not exist: {repo_path}")
                return []

            self.logger.debug(f"Starting {self.display_name} scan of {repo_path_obj}")

            # Find config
            config_path = self.find_config(repo_path_obj)

            # Build and run command
            cmd = self.build_scan_command(repo_path_obj, output_file, config_path)
            env = self.get_scan_env(config_path) # Get env specific to this config
            
            self.logger.debug(f"{self.display_name} command: {' '.join(cmd)}")

            # Delete old output file
            if output_file.exists():
                output_file.unlink()

            # Run scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False,
                cwd=str(repo_path_obj),
                env=env
            )

            self.logger.debug(f"{self.display_name} completed with return code: {result.returncode}")

            # Check for fatal errors (returncode 2 is common for config errors)
            if result.returncode >= 2:
                # Retry logic for broken repo configs
                # If we were using a repo-specific config, try falling back to the bundled one
                if config_path and config_path != self.get_bundled_config_path(repo_path_obj):
                    self.logger.warning(f"⚠️  {self.display_name} repository configuration failed (likely missing plugins or dependencies).")
                    self.logger.info(f"🔄 Falling back to AppSec-Sentinel default configuration for {self.display_name}...")
                    
                    fallback_config = self.get_bundled_config_path(repo_path_obj)
                    if fallback_config:
                        # Rebuild command with fallback config
                        retry_cmd = self.build_scan_command(repo_path_obj, output_file, fallback_config)
                        retry_env = self.get_scan_env(fallback_config) # Get env specific to fallback config (CRITICAL FIX)
                        
                        self.logger.debug(f"Retry {self.display_name} command: {' '.join(retry_cmd)}")
                        
                        result = subprocess.run(
                            retry_cmd,
                            capture_output=True,
                            text=True,
                            timeout=300,
                            shell=False,
                            cwd=str(repo_path_obj),
                            env=retry_env
                        )
                        
                        # Check result again after retry
                        if result.returncode < 2:
                            self.logger.info(f"✅ {self.display_name} recovered successfully using default config.")

                # If still failing after retry (or no retry possible)
                if result.returncode >= 2:
                    self.logger.error(f"{self.display_name} failed with exit code {result.returncode}")
                    if result.stderr:
                        self.logger.debug(f"Error output: {result.stderr[:500]}")
                    return []

            # Parse results
            findings = self.parse_output(output_file, repo_path_obj)

            self.logger.info(f"✅ {self.display_name}: {len(findings)} code quality issues found")
            return findings

        except subprocess.TimeoutExpired:
            self.logger.error(f"{self.display_name} timed out after 5 minutes")
            return []
        except FileNotFoundError:
            self.logger.warning(f"{self.display_name} command not found")
            return []
        except Exception as e:
            self.logger.error(f"{self.display_name} scan failed: {e}")
            return []

    def parse_output(self, output_file: Path, repo_path: Path) -> List[Dict]:
        """
        Parse scanner output file and normalize findings.

        Override this if your scanner doesn't output JSON,
        or needs custom parsing logic.
        """
        if not output_file.exists():
            self.logger.warning(f"{self.display_name} did not produce an output file")
            return []

        try:
            with open(output_file, 'r') as f:
                raw_results = json.load(f)

            findings = []
            results_list = self.extract_findings_from_output(raw_results)

            for raw_finding in results_list:
                try:
                    normalized = self.normalize_finding(raw_finding, repo_path)
                    findings.append(normalized)
                except Exception as e:
                    self.logger.debug(f"Failed to normalize finding: {e}")

            return findings

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse {self.display_name} JSON output: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Failed to parse {self.display_name} output: {e}")
            return []

    def extract_findings_from_output(self, raw_results: any) -> List[Dict]:
        """
        Extract list of findings from raw JSON output.

        Override this if your tool's JSON structure is nested.
        Default assumes raw_results is already a list.
        """
        if isinstance(raw_results, list):
            return raw_results
        elif isinstance(raw_results, dict) and 'results' in raw_results:
            return raw_results['results']
        else:
            return []
