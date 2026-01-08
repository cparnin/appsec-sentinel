"""
ESLint code quality scanner integration for JavaScript and TypeScript projects.

This module runs ESLint to detect code quality issues, best practices violations,
and potential bugs in JavaScript/TypeScript codebases.
"""

import subprocess
import json
from pathlib import Path
import logging
import os
import sys

from config import format_subprocess_error, SCAN_EXCLUDE_PATTERNS
from .validation import validate_repo_path
from logging_config import get_logger

logger = get_logger(__name__)


def check_eslint_installed() -> bool:
    """
    Check if ESLint is available in the system.

    Returns:
        bool: True if ESLint is installed and accessible
    """
    try:
        result = subprocess.run(
            ['eslint', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            logger.debug(f"ESLint found: {version}")
            return True
        return False
    except FileNotFoundError:
        logger.debug("ESLint not found in PATH")
        return False
    except Exception as e:
        logger.debug(f"Error checking ESLint installation: {e}")
        return False


def _map_eslint_severity(eslint_severity: int) -> str:
    """
    Map ESLint severity levels to AppSec-Sentinel standard severity.

    ESLint uses:
    - 0: off
    - 1: warn
    - 2: error

    Args:
        eslint_severity: ESLint severity code (0, 1, or 2)

    Returns:
        str: Normalized severity ('low', 'medium', 'high')
    """
    severity_map = {
        0: 'low',     # Off (shouldn't appear in results)
        1: 'medium',  # Warning
        2: 'high'     # Error
    }
    return severity_map.get(eslint_severity, 'medium')


def _normalize_eslint_finding(file_path: str, message: dict, repo_path: Path) -> dict:
    """
    Convert ESLint finding to AppSec-Sentinel standard format.

    Args:
        file_path: Path to the file with the finding
        message: ESLint message object
        repo_path: Root path of the repository

    Returns:
        dict: Normalized finding in AppSec-Sentinel format
    """
    # Make path relative to repo root for consistency
    try:
        relative_path = Path(file_path).relative_to(repo_path)
    except ValueError:
        relative_path = Path(file_path)

    normalized_severity = _map_eslint_severity(message.get('severity', 1))

    return {
        'tool': 'eslint',
        'category': 'code_quality',
        'severity': normalized_severity,
        'check_id': message.get('ruleId', 'eslint-rule'),
        'path': str(relative_path),
        'start': {
            'line': message.get('line', 0),
            'col': message.get('column', 0)
        },
        'end': {
            'line': message.get('endLine', message.get('line', 0)),
            'col': message.get('endColumn', message.get('column', 0))
        },
        'extra': {
            'message': message.get('message', ''),
            'metadata': {
                'category': 'code_quality',
                'subcategory': 'best-practice',
                'technology': ['javascript', 'typescript'],
                'confidence': 'HIGH'  # ESLint rules are well-tested
            }
        }
    }


def run_eslint(repo_path: str, output_dir: str = None) -> list:
    """
    Run ESLint code quality scanner on JavaScript/TypeScript files.

    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)

    Returns:
        list: List of findings in standardized AppSec-Sentinel format
    """
    try:
        # Check if ESLint is installed
        if not check_eslint_installed():
            logger.warning("⚠️ ESLint not installed - skipping code quality scan for JavaScript/TypeScript")
            logger.info("💡 Install ESLint: npm install -g eslint")
            return []

        # Detect ESLint version early (needed for config logic)
        major_version = 8  # Default conservative assumption
        try:
            version_result = subprocess.run(
                ['eslint', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if version_result.returncode == 0:
                version_str = version_result.stdout.strip()
                # Extract major version (e.g., "v9.37.0" -> 9 or "9.37.0" -> 9)
                major_version = int(version_str.split('.')[0].replace('v', ''))
                logger.debug(f"Detected ESLint version: {version_str} (Major: {major_version})")
        except Exception as e:
            logger.warning(f"Failed to detect ESLint version, assuming v8 compatible: {e}")

        # Set up output directory (use absolute path since ESLint runs from repo_path)
        if output_dir is None:
            from config import BASE_OUTPUT_DIR
            output_path = (Path(BASE_OUTPUT_DIR) / "raw").resolve()
        else:
            output_path = Path(output_dir).resolve()

        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / "eslint.json"

        # Validate repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            logger.error(f"Repository path validation failed: {repo_path}")
            return []

        logger.debug(f"Starting ESLint scan of {repo_path_obj}")

        # Check for package.json (indicates Node.js project)
        package_json = repo_path_obj / "package.json"
        has_package_json = package_json.exists()
        package_has_eslint = False

        if has_package_json:
            try:
                with open(package_json, 'r') as f:
                    pkg = json.load(f)
                    package_has_eslint = 'eslintConfig' in pkg
            except Exception:
                pass

        # Check for legacy configs (.eslintrc.*)
        legacy_configs = [
            repo_path_obj / ".eslintrc.json",
            repo_path_obj / ".eslintrc.js",
            repo_path_obj / ".eslintrc.cjs",
            repo_path_obj / ".eslintrc.yml",
            repo_path_obj / ".eslintrc.yaml"
        ]
        has_legacy_file = any(c.exists() for c in legacy_configs)
        
        # Check for flat configs (eslint.config.*)
        flat_configs = [
            repo_path_obj / "eslint.config.js",
            repo_path_obj / "eslint.config.mjs",
            repo_path_obj / "eslint.config.cjs"
        ]
        has_flat_file = any(c.exists() for c in flat_configs)

        has_legacy_config = has_legacy_file or package_has_eslint
        has_flat_config = has_flat_file
        has_config = has_legacy_config or has_flat_config

        # Use AppSec-Sentinel bundled config as fallback if repo has none
        bundled_config_path = None
        if not has_config:
            logger.info("📋 No ESLint config in repo - using AppSec-Sentinel default config for code quality scan")
            
            # Get path to AppSec-Sentinel configs directory
            scanner_dir = Path(__file__).parent
            appsec_root = scanner_dir.parent.parent  # src/scanners -> src -> root
            configs_dir = appsec_root / "configs"

            if major_version >= 9:
                # ESLint v9+ uses flat config (eslint.config.js)
                bundled_config_path = configs_dir / "eslint.config.js"
                logger.debug(f"Using ESLint v{major_version} flat config: {bundled_config_path}")
            else:
                # ESLint v8 and below use legacy format (.eslintrc.json)
                bundled_config_path = configs_dir / "eslintrc.v8.json"
                logger.debug(f"Using ESLint v{major_version} legacy config: {bundled_config_path}")

            if not bundled_config_path.exists():
                logger.error(f"Bundled ESLint config not found: {bundled_config_path}")
                return []

        # Prepare environment variables
        env = os.environ.copy()
        
        # KEY FIX: ESLint 9+ ignores legacy configs unless ESLINT_USE_FLAT_CONFIG=false
        if major_version >= 9 and has_legacy_config and not has_flat_config:
            logger.info("ℹ️  Detected legacy ESLint config with ESLint v9+. Enabling compatibility mode (ESLINT_USE_FLAT_CONFIG=false).")
            env['ESLINT_USE_FLAT_CONFIG'] = 'false'

        # Build ESLint command
        cmd = ['eslint']

        # Add bundled config if using fallback
        if bundled_config_path:
            cmd.extend(['--config', str(bundled_config_path)])

        # Scan all JS/TS files
        cmd.extend([
            '.',
            '--format', 'json',
            '--output-file', str(output_file),
            '--no-error-on-unmatched-pattern'  # Don't fail if no files match
        ])

        # Add file extensions to scan
        cmd.extend([
            '--ext', '.js,.jsx,.ts,.tsx,.mjs,.cjs'
        ])

        # Add exclusion patterns
        for pattern in SCAN_EXCLUDE_PATTERNS:
            cmd.extend(['--ignore-pattern', pattern])

        # Add common exclusions
        cmd.extend([
            '--ignore-pattern', '*.min.js',
            '--ignore-pattern', '*.bundle.js',
            '--ignore-pattern', 'webpack.config.js',
            '--ignore-pattern', 'jest.config.js'
        ])

        logger.debug(f"ESLint command: {' '.join(cmd)}")

        # Delete old output file
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old ESLint output file: {output_file}")

        # Run ESLint
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
            cwd=str(repo_path_obj),
            env=env
        )

        logger.debug(f"ESLint completed with return code: {result.returncode}")

        # ESLint returns:
        # 0 = no errors
        # 1 = linting errors found (this is expected!)
        # 2 = fatal error
        if result.returncode == 2:
            # Check if we should retry with bundled config
            # Only retry if we weren't already using the bundled config
            if not bundled_config_path:
                logger.warning("⚠️  Repository ESLint configuration failed (likely missing plugins or dependencies).")
                logger.info("🔄 Falling back to AppSec-Sentinel default configuration...")
                
                # Determine correct bundled config based on version
                scanner_dir = Path(__file__).parent
                appsec_root = scanner_dir.parent.parent
                configs_dir = appsec_root / "configs"
                
                if major_version >= 9:
                    fallback_config = configs_dir / "eslint.config.js"
                else:
                    fallback_config = configs_dir / "eslintrc.v8.json"
                
                if fallback_config.exists():
                    # Rebuild command with fallback config
                    retry_cmd = ['eslint']
                    retry_cmd.extend(['--config', str(fallback_config)])
                    
                    # Add rest of the arguments (skip index 1 if it was --config, but here we just rebuild)
                    retry_cmd.extend([
                        '.',
                        '--format', 'json',
                        '--output-file', str(output_file),
                        '--no-error-on-unmatched-pattern',
                        '--ext', '.js,.jsx,.ts,.tsx,.mjs,.cjs'
                    ])
                    
                    for pattern in SCAN_EXCLUDE_PATTERNS:
                        retry_cmd.extend(['--ignore-pattern', pattern])
                        
                    retry_cmd.extend([
                        '--ignore-pattern', '*.min.js',
                        '--ignore-pattern', '*.bundle.js', 
                        '--ignore-pattern', 'webpack.config.js',
                        '--ignore-pattern', 'jest.config.js'
                    ])
                    
                    # Clean environment for retry (remove compatibility flag if switching to v9 flat config)
                    retry_env = os.environ.copy()
                    
                    logger.debug(f"Retry ESLint command: {' '.join(retry_cmd)}")
                    
                    result = subprocess.run(
                        retry_cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        shell=False,
                        cwd=str(repo_path_obj),
                        env=retry_env
                    )
            
            # Check result again after retry (or if we didn't retry)
            if result.returncode == 2:
                error_details = format_subprocess_error('eslint', result.returncode, result.stderr, result.stdout)
                logger.error(error_details)
                return []

        # Check if output file was created
        if not output_file.exists():
            logger.warning("ESLint did not produce an output file")
            # This might mean no JS/TS files were found
            logger.debug(f"ESLint stderr: {result.stderr[:500]}")
            return []

        # Parse ESLint JSON output
        with open(output_file, 'r') as f:
            eslint_results = json.load(f)

        logger.debug(f"ESLint found results for {len(eslint_results)} files")

        # Normalize findings
        findings = []
        for file_result in eslint_results:
            file_path = file_result.get('filePath', '')
            messages = file_result.get('messages', [])

            for message in messages:
                # Skip messages that are just warnings about missing config
                if 'no-unused-vars' in message.get('ruleId', ''):
                    # This is a common code quality issue - include it
                    pass

                normalized = _normalize_eslint_finding(file_path, message, repo_path_obj)
                findings.append(normalized)

        logger.info(f"✅ ESLint: {len(findings)} code quality issues found")

        return findings

    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('eslint', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return []
    except FileNotFoundError:
        logger.warning("ESLint command not found - skipping JavaScript/TypeScript code quality scan")
        logger.info("💡 Install ESLint: npm install -g eslint")
        return []
    except Exception as e:
        error_msg = format_subprocess_error('eslint', 1, str(e))
        logger.error(error_msg)
        return []
