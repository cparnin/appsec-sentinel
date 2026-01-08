"""
ESLint code quality scanner integration for JavaScript and TypeScript projects.

This module runs ESLint to detect code quality issues, best practices violations,
and potential bugs in JavaScript/TypeScript codebases.
"""

import os
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional

from config import SCAN_EXCLUDE_PATTERNS
from .quality_scanner_base import QualityScannerBase
from logging_config import get_logger

logger = get_logger(__name__)


class EslintScanner(QualityScannerBase):
    @property
    def tool_name(self) -> str:
        return 'eslint'

    @property
    def display_name(self) -> str:
        return 'ESLint'

    @property
    def check_command(self) -> List[str]:
        return ['eslint', '--version']

    @property
    def languages(self) -> List[str]:
        return ['javascript', 'typescript']

    def get_repo_config_paths(self, repo_path: Path) -> List[Path]:
        """
        Return list of possible config file paths in repo.
        Supports both legacy (.eslintrc.*) and flat (eslint.config.js) configs.
        """
        # Common usage: flat config first, then legacy
        configs = [
            repo_path / "eslint.config.js",
            repo_path / "eslint.config.mjs",
            repo_path / "eslint.config.cjs",
            repo_path / ".eslintrc.js",
            repo_path / ".eslintrc.json",
            repo_path / ".eslintrc.yml",
            repo_path / ".eslintrc.yaml",
            repo_path / ".eslintrc",
            repo_path / "package.json"  # ESLint can be configured in package.json
        ]
        return configs

    def _get_major_version(self) -> int:
        """Detect ESLint major version."""
        try:
            result = subprocess.run(
                ['eslint', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Output format usually "v9.x.x" or "8.x.x"
                version_str = result.stdout.strip()
                if version_str.startswith('v'):
                    version_str = version_str[1:]
                return int(version_str.split('.')[0])
        except Exception:
            pass
        return 8  # Fallback assumption

    def get_bundled_config_path(self, repo_path: Path) -> Optional[Path]:
        """Return path to AppSec-Sentinel bundled config file based on version."""
        major_version = self._get_major_version()
        
        if major_version >= 9:
            config = self.configs_dir / "eslint.config.js"
            logger.debug(f"Selected ESLint v{major_version} flat config: {config}")
            return config
        else:
            config = self.configs_dir / "eslintrc.v8.json"
            logger.debug(f"Selected ESLint v{major_version} legacy config: {config}")
            return config

    def get_scan_env(self, config_path: Optional[Path]) -> Dict[str, str]:
        """
        Get environment variables for ESLint scan.
        Sets ESLINT_USE_FLAT_CONFIG=false for legacy configs with ESLint v9+.
        """
        env = os.environ.copy()
        
        # Determine if we need compatibility flag for v9
        major_version = self._get_major_version()
        if major_version >= 9 and config_path:
            # Check if using legacy config
            is_flat = str(config_path).endswith(('eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs'))
            if not is_flat:
                # Legacy config with ESLint v9+ needs compatibility mode
                env['ESLINT_USE_FLAT_CONFIG'] = 'false'
                self.logger.info("ℹ️  Detected legacy ESLint config with ESLint v9+. Enabling compatibility mode (ESLINT_USE_FLAT_CONFIG=false).")
        
        return env

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Optional[Path]) -> List[str]:
        """Build the command to run the scanner."""
        cmd = ['eslint']
        
        if config_path:
            cmd.extend(['--config', str(config_path)])

        # Scan all files recursively
        cmd.extend([
            '.',
            '--format', 'json',
            '--output-file', str(output_file),
            '--no-error-on-unmatched-pattern'
        ])

        # Add file extensions
        cmd.extend([
            '--ext', '.js,.jsx,.ts,.tsx,.mjs,.cjs'
        ])

        # Add exclusion patterns
        # paranoid check to prevent 'NoneType' iteration crash
        if SCAN_EXCLUDE_PATTERNS:
            for pattern in SCAN_EXCLUDE_PATTERNS:
                cmd.extend(['--ignore-pattern', pattern])

        cmd.extend([
            '--ignore-pattern', '*.min.js',
            '--ignore-pattern', '*.bundle.js',
            '--ignore-pattern', 'webpack.config.js',
            '--ignore-pattern', 'jest.config.js'
        ])

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> Dict:
        """Normalize ESLint finding."""
        file_path_abs = raw_finding.get('filePath', '')
        try:
             # Make relative path
             file_path = str(Path(file_path_abs).relative_to(repo_path))
        except ValueError:
             file_path = file_path_abs

        messages = raw_finding.get('messages', [])
        # We need to flatten findings: ESLint returns list of files, each with list of findings.
        # But QualityScannerBase.parse_output handles list vs dict.
        # Wait, ESLint output is List[FileResult].
        # QualityScannerBase.run_scan -> parse_output -> extract_findings_from_output
        # returns the list of file objects.
        # Then Loop iterates file objects and calls normalize_finding.
        # BUT normalize_finding is supposed to return ONE finding dict.
        # Here one Input Item (FileResult) contains MANY findings.
        # This breaks the 1-to-1 assumption of QualityScannerBase.normalize_finding if we use default loop.
        
        # We need to override parse_output or extract_findings_from_output to flatten it first?
        # Yes. Let's override extract_findings_from_output to flatten content.
        raise NotImplementedError("This shouldn't be called directly for nested ESLint output")

    def extract_findings_from_output(self, raw_results: any) -> List[Dict]:
        """
        Flatten ESLint results: [ {filePath:..., messages:[...]} ]
        into list of individual finding objects: [ {filePath:..., message:...}, ... ]
        """
        if not isinstance(raw_results, list):
            return []
            
        flat_findings = []
        for file_result in raw_results:
            path = file_result.get('filePath', 'unknown')
            messages = file_result.get('messages', [])
            for msg in messages:
                # Attach path to message so normalize can use it
                msg['filePath'] = path
                flat_findings.append(msg)
        return flat_findings

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> Dict:
        # Now raw_finding is a single message dict with 'filePath' injected
        try:
            file_path = Path(raw_finding.get('filePath', '')).relative_to(repo_path)
        except (ValueError, TypeError):
             file_path = Path(raw_finding.get('filePath', 'unknown'))

        severity_map = {
            1: 'medium',  # Warning
            2: 'high'     # Error
        }
        severity_int = raw_finding.get('severity', 1)
        severity = severity_map.get(severity_int, 'medium')

        rule_id = raw_finding.get('ruleId', 'eslint-error')
        
        return {
            'tool': 'eslint',
            'category': 'code_quality',
            'severity': severity,
            'check_id': rule_id if rule_id else 'eslint.parsing-error',
            'path': str(file_path),
            'start': {
                'line': raw_finding.get('line', 0),
                'col': raw_finding.get('column', 0)
            },
            'end': {
                'line': raw_finding.get('endLine', 0),
                'col': raw_finding.get('endColumn', 0)
            },
            'extra': {
                'message': raw_finding.get('message', ''),
                'metadata': {
                    'category': 'code_quality',
                    'technology': ['javascript', 'typescript'],
                    'confidence': 'HIGH',
                    'rule_id': rule_id
                }
            }
        }

# Wrapper function for main.py
def run_eslint(repo_path: str, output_dir: str = None) -> list:
    scanner = EslintScanner()
    return scanner.run_scan(repo_path, output_dir)
