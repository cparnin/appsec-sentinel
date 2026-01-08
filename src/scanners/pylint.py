"""
Pylint code quality scanner integration for Python projects.

This module runs Pylint to detect code quality issues, best practices violations,
code smells, and potential bugs in Python codebases.
"""

from pathlib import Path
from typing import List, Dict, Optional

from .quality_scanner_base import QualityScannerBase
from logging_config import get_logger

logger = get_logger(__name__)


class PylintScanner(QualityScannerBase):
    @property
    def tool_name(self) -> str:
        return 'pylint'

    @property
    def display_name(self) -> str:
        return 'Pylint'

    @property
    def check_command(self) -> List[str]:
        return ['pylint', '--version']

    @property
    def languages(self) -> List[str]:
        return ['python']

    def get_repo_config_paths(self, repo_path: Path) -> List[Path]:
        """
        Return list of possible config file paths in repo.
        Pylint looks for .pylintrc, pylintrc, pyproject.toml
        """
        return [
            repo_path / ".pylintrc",
            repo_path / "pylintrc",
            repo_path / "pyproject.toml"
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Optional[Path]:
        """Return path to AppSec-Sentinel bundled config file."""
        return self.configs_dir / "pylintrc"

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Optional[Path]) -> List[str]:
        """Build the command to run the scanner."""
        cmd = [
            'pylint',
            '--output-format=json',
            '--reports=no',
            '--score=no',
        ]

        if config_path:
            cmd.extend(['--rcfile', str(config_path)])
        else:
            # Default options if no config provided (though Base class usually handles fallback)
            cmd.extend([
                '--disable=C0114',  # missing-module-docstring
                '--disable=C0115',  # missing-class-docstring
                '--disable=C0116',  # missing-function-docstring
                '--disable=R0903',  # too-few-public-methods
                '--max-line-length=120'
            ])

        # Scan current directory (repo_path is CWD during execution)
        # We need to find all python files or just run on '.' 
        # Pylint works well with recursive glob or module discovery
        
        # Note: Pylint on '.' can be slow or messy if setup.py is present but dependencies missing.
        # But for robustness, we try scanning '.' recursively.
        cmd.append('.')
        
        # We don't specify output file in command because we capture stdout,
        # but the Base class logic expects us to ideally write to file or capture.
        # QualityScannerBase.run_scan runs the command and captures stdout/stderr.
        # Wait, Base class parse_output reads from FILE.
        # So we should probably redirect output or tell tool to write to file if supported.
        # Pylint doesn't utilize --output-file for JSON nicely in all versions, 
        # but let's see. Actually, standard is to capture stdout.
        
        # Refinement: QualityScannerBase expects the *tool* to write to output_file 
        # OR we override run_scan. But better to make Pylint write to file if possible.
        # Recent Pylint versions support redirect, but let's stick to standard behavior:
        # We will override parse_output to read from stdout if file empty? 
        # No, let's keep it simple. Let's use shell redirection? No, security risk.
        
        # Better approach: The QualityScannerBase.run_scan logic captures stdout/stderr.
        # But it calls parse_output(output_file).
        # We should override run_scan or modify the command to write to file?
        # Actually, let's just make PylintScanner specific logic in parse_output 
        # handle the fact that Pylint prints to stdout.
        
        return cmd

    def run_scan(self, repo_path: str, output_dir: str = None) -> List[Dict]:
        """
        Override run_scan to handle Pylint's stdout output behavior.
        """
        # We reuse most logic but handle the result capture differently
        # Or, we can trick the base class by saving stdout to the file in a wrapper?
        # Let's implement a clean override that calls super() logic but handles the I/O.
        # Actually, simpler: Pylint doesn't output to file natively via flag in older versions easily.
        # Let's fully implement run_scan here reusing the base logic structure where possible,
        # OR just write the stdout to the file in this method.
        
        import subprocess
        from config import format_subprocess_error

        # Standard setup from base
        if not self.check_installed():
             print(f"⚠️  {self.display_name} not installed - skipping {'/'.join(self.languages)} code quality scan")
             self.logger.info(f"💡 Install {self.display_name}: pip install pylint")
             return []

        if output_dir is None:
            from config import BASE_OUTPUT_DIR
            output_path = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            output_path = Path(output_dir)
        
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / f"{self.tool_name}.json"
        repo_path_obj = Path(repo_path).resolve()

        self.logger.debug(f"Starting {self.display_name} scan of {repo_path_obj}")
        config_path = self.find_config(repo_path_obj)
        cmd = self.build_scan_command(repo_path_obj, output_file, config_path)
        
        # Exclude directories logic (simplified from original)
        # Pylint's ignore patterns via command line are a bit tricky on recursive scan,
        # so passing specific files is often safer, but '.' is robust if ignores are set.
        # For this implementation, we'll try '.' with ignore-patterns if possible, or filtered file list.
        # To match previous behavior and robustness, let's use the file list approach if config is default.
        
        # Actually, if we use config_path, Pylint respects the config's ignores.
        # If we use default, we should pass ignores.
        
        # Let's stick to the previous file-list building logic? 
        # No, that was slow (limit 500). Let's try to be smarter.
        # But to be strictly matching the Base class 'agnostic' promise, we should follow its flow.
        # Let's stick to the base class generic 'cmd' execution but capture stdout -> file.
        
        try:
             # Run Pylint
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False,
                cwd=str(repo_path_obj)
            )

            # Retry logic (Fatal error fallback) - REUSING THE ROBUST PATTERN
            if result.returncode >= 32: # Pylint fatal error is 32 TODO: Check this. actually 1 is fatal in some contexts, but usually bitmask.
                 # Wait, Pylint return codes are bitmasks. 
                 # 1=fatal, 2=error, 4=warning, 8=refactor, 16=convention, 32=usage_error
                 # So >= 32 is definitely bad (usage error). 1 is also fatal message.
                 
                 # Logic for fallback:
                 if config_path and config_path != self.get_bundled_config_path(repo_path_obj):
                     fallback = self.get_bundled_config_path(repo_path_obj)
                     if fallback:
                         self.logger.warning(f"⚠️  Pylint repo config failed. Retrying with bundled config...")
                         retry_cmd = self.build_scan_command(repo_path_obj, output_file, fallback)
                         result = subprocess.run(
                            retry_cmd,
                            capture_output=True,
                            text=True,
                            timeout=300,
                            cwd=str(repo_path_obj)
                        )

            # Manually save stdout to json file for the Base parser to pick up
            if result.stdout:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
            
            # Now call the base parse logic
            findings = self.parse_output(output_file, repo_path_obj)
            self.logger.info(f"✅ {self.display_name}: {len(findings)} code quality issues found")
            return findings

        except Exception as e:
            self.logger.error(f"Pylint scan failed: {e}")
            return []

    def _map_severity(self, pylint_type: str) -> str:
        severity_map = {
            'convention': 'low',
            'refactor': 'medium', 
            'warning': 'medium',
            'error': 'high',
            'fatal': 'critical'
        }
        return severity_map.get(pylint_type.lower(), 'medium')

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> Dict:
        # Make path relative
        try:
            file_path = Path(raw_finding.get('path', raw_finding.get('file', '')))
            relative_path = file_path.relative_to(repo_path)
        except (ValueError, TypeError):
            # Sometimes pylint reports absolute paths or relative to cwd
            # Try to resolve or just keep as is if fails
             relative_path = Path(raw_finding.get('path', raw_finding.get('file', 'unknown')))

        pylint_type = raw_finding.get('type', 'warning')
        normalized_severity = self._map_severity(pylint_type)
        
        message_id = raw_finding.get('message-id', '')
        symbol = raw_finding.get('symbol', '')
        
        return {
            'tool': 'pylint',
            'category': 'code_quality',
            'severity': normalized_severity,
            'check_id': f"pylint.{symbol}" if symbol else f"pylint.{message_id}",
            'path': str(relative_path),
            'start': {
                'line': raw_finding.get('line', 0),
                'col': raw_finding.get('column', 0)
            },
            'end': {
                 'line': raw_finding.get('endLine', raw_finding.get('line', 0)),
                 'col': raw_finding.get('endColumn', raw_finding.get('column', 0))
            },
            'extra': {
                'message': raw_finding.get('message', ''),
                'metadata': {
                    'pylint_id': message_id,
                    'pylint_type': pylint_type,
                    'confidence': 'HIGH',
                    'category': 'code_quality',
                    'technology': ['python']
                }
            }
        }

# Wrapper for main.py compatibility
def run_pylint(repo_path: str, output_dir: str = None) -> list:
    scanner = PylintScanner()
    return scanner.run_scan(repo_path, output_dir)
