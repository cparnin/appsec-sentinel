#!/usr/bin/env python3
"""
AppSec-Sentinel - Interactive CLI

🔒 Comprehensive security scanner with AI-powered auto-remediation

This is the main entry point for AppSec-Sentinel, providing:
- Interactive repository selection with smart discovery
- Parallel scanning (Semgrep, Gitleaks, Trivy)
- Git-aware scanning (only changed files for performance)
- Comprehensive reporting with business context
- Cross-file vulnerability analysis with deep codebase understanding
- AI-powered auto-remediation creating separate PRs
- Rich progress bars and comprehensive reporting

Architecture:
- Async/await for concurrent scanning (60-70% faster)
- Cross-file analysis for context-aware vulnerability detection
- Cross-file analysis provides context-aware vulnerability correlation
- Separate PR creation for SAST fixes and dependency updates
- Pipeline safety - never modifies workflow files

Usage:
    python main.py              # Interactive mode for security consultants
"""

# Load environment variables from .env file (contains OpenAI API key)
from dotenv import load_dotenv
load_dotenv()

from pathlib import Path
import logging
import os

# Setup logging early
from logging_config import setup_logging, get_logger, set_debug_mode
setup_logging(level=os.getenv('APPSEC_LOG_LEVEL', 'INFO'))
import requests
from typing import Optional, List, Dict, Any, Tuple
import asyncio
import time
import subprocess
import json
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console

# Import configuration constants
from config import (
    TOOL_INSTALL_URLS, MAX_REPO_SEARCH_DEPTH, DEFAULT_TOOL_CHECK_TIMEOUT,
    DEFAULT_MANUAL_REVIEW_TIME, format_subprocess_error, ENABLE_GIT_AWARE_SCANNING,
    MAX_CHANGED_FILES_FOR_FULL_SCAN, GIT_DIFF_CONTEXT_LINES, BASE_OUTPUT_DIR
)

# Import path utilities for multi-repo/branch output structure
from path_utils import (
    get_output_path, cleanup_old_scans, setup_output_directories,
    get_report_path, get_pr_findings_path
)

# Import our scanner modules
from scanners.semgrep import run_semgrep      # Static Application Security Testing (SAST)
from scanners.gitleaks import run_gitleaks    # Secrets detection in git history
from scanners.trivy import run_trivy_scan         # Software Composition Analysis (dependency vulnerabilities)
from scanners.validation import detect_languages  # Language detection for code quality linters
from reporting.html import generate_html_report  # Pretty HTML reports for detailed review

# Import code quality linters (graceful fallback if not installed)
try:
    from scanners.eslint import run_eslint
    ESLINT_AVAILABLE = True
except ImportError:
    ESLINT_AVAILABLE = False

try:
    from scanners.pylint import run_pylint
    PYLINT_AVAILABLE = True
except ImportError:
    PYLINT_AVAILABLE = False

try:
    from scanners.checkstyle import run_checkstyle
    CHECKSTYLE_AVAILABLE = True
except ImportError:
    CHECKSTYLE_AVAILABLE = False

try:
    from scanners.golangci_lint import run_golangci_lint
    GOLANGCI_AVAILABLE = True
except ImportError:
    GOLANGCI_AVAILABLE = False

try:
    from scanners.rubocop import run_rubocop
    RUBOCOP_AVAILABLE = True
except ImportError:
    RUBOCOP_AVAILABLE = False

try:
    from scanners.clippy import run_clippy
    CLIPPY_AVAILABLE = True
except ImportError:
    CLIPPY_AVAILABLE = False

try:
    from scanners.phpstan import run_phpstan
    PHPSTAN_AVAILABLE = True
except ImportError:
    PHPSTAN_AVAILABLE = False

# Configure logging for minimal output
logging.basicConfig(
    level=logging.ERROR,  # Only show errors
    format='%(message)s'  # Simple format
)

# Reduce noise from all libraries and scanners
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("openai").setLevel(logging.ERROR)
logging.getLogger("anthropic").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("auto_remediation").setLevel(logging.ERROR)
logging.getLogger("sbom_generator").setLevel(logging.ERROR)
logging.getLogger("enhanced_analyzer").setLevel(logging.ERROR)
logging.getLogger("scanners.trivy").setLevel(logging.ERROR)
logging.getLogger("scanners.semgrep").setLevel(logging.ERROR)
logging.getLogger("scanners.gitleaks").setLevel(logging.ERROR)
logging.getLogger("reporting.html").setLevel(logging.ERROR)

logger = get_logger(__name__)

def validate_repo_path(repo_path: str) -> Path:
    """
    Safely validate that the repository path exists and is accessible with enhanced security.
    
    This prevents directory traversal attacks, validates permissions, and ensures we're
    scanning a valid repository before spending time on security analysis.
    
    Args:
        repo_path: User-provided path to repository to scan
        
    Returns:
        Path: Resolved absolute path to repository
        
    Raises:
        ValueError: If path doesn't exist, isn't a directory, or fails security checks
        PermissionError: If path is not readable
    """
    # Input sanitization
    if not repo_path or not isinstance(repo_path, str):
        raise ValueError("Repository path must be a non-empty string")
    
    # Remove any null bytes (security)
    clean_path = repo_path.replace('\x00', '')
    if clean_path != repo_path:
        raise ValueError("Invalid characters in repository path")
    
    # Check for suspicious patterns that could indicate command injection
    dangerous_patterns = [';', '|', '&', '$', '`', '$(', '${']
    if any(pattern in clean_path for pattern in dangerous_patterns):
        raise ValueError("Potentially dangerous characters in repository path")
    
    # Check path length to prevent resource exhaustion  
    if len(clean_path) > 4096:  # Common filesystem limit
        raise ValueError("Repository path too long (max 4096 characters)")
    
    try:
        path = Path(clean_path).resolve()
        
        # Additional path traversal protection
        # Ensure resolved path doesn't escape expected boundaries
        if '..' in clean_path:
            # Check if the resolved path significantly differs from input (potential traversal)
            original_parts = Path(clean_path).parts
            resolved_parts = path.parts
            if len(resolved_parts) < len(original_parts) - clean_path.count('..'):
                raise ValueError("Path traversal attempt detected")
                
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid repository path format: {e}")
    
    # Basic existence and type checks
    if not path.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")
    
    # Permission checks
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Repository path is not readable: {path}")
    
    # Security: Prevent scanning system directories
    system_dirs = {
        Path('/etc'), Path('/sys'), Path('/proc'), Path('/dev'),
        Path('/boot'), Path('/root'), Path('/var/log'),
        Path('C:/Windows'), Path('C:/System32'), Path('C:/Program Files')
    }
    
    # Check if path is or contains system directories
    for sys_dir in system_dirs:
        try:
            if sys_dir.exists() and (path == sys_dir or sys_dir in path.parents or path in sys_dir.parents):
                raise ValueError(f"Cannot scan system directory: {path}")
        except (OSError, ValueError):
            # Skip if system directory doesn't exist or can't be compared
            continue
    
    # Warn about very large directories
    try:
        # Quick size check - count items in root directory
        item_count = sum(1 for _ in path.iterdir() if _.is_file() or _.is_dir())
        if item_count > 10000:
            logger.warning(f"Large directory detected ({item_count} items). Scan may take a long time.")
    except (OSError, PermissionError):
        # Can't count items, that's ok
        pass
    
    # Verify it's actually a git repository (optional but helpful)
    git_dir = path / '.git'
    if not git_dir.exists():
        logger.warning(f"Directory is not a git repository: {path}")
        logger.warning("Some scanners (like gitleaks) require git history to function properly")
    
    return path

def validate_environment_config() -> Dict[str, Any]:
    """
    Validate environment configuration and return sanitized values.
    
    This ensures that environment variables are properly formatted and within
    acceptable ranges to prevent configuration-related issues.
    
    Returns:
        dict: Validated configuration values with defaults applied
        
    Raises:
        ValueError: If critical configuration is invalid
    """
    config = {}
    
    # Validate timeouts (must be positive integers)
    timeout_vars = {
        'SEMGREP_TIMEOUT': (300, 60, 1800),  # (default, min, max)
        'GITLEAKS_TIMEOUT': (120, 30, 600),
        'TRIVY_TIMEOUT': (300, 60, 1800)
    }
    
    for var, (default, min_val, max_val) in timeout_vars.items():
        try:
            value = int(os.getenv(var, default))
            if value < min_val or value > max_val:
                logger.warning(f"{var} value {value} out of range [{min_val}-{max_val}], using default {default}")
                value = default
            config[var.lower()] = value
        except ValueError:
            logger.warning(f"Invalid {var} value, using default {default}")
            config[var.lower()] = default
    
    # Validate AI provider
    ai_provider = os.getenv('AI_PROVIDER', 'openai').strip().lower()
    if ai_provider not in ['openai', 'claude', 'aws_bedrock']:
        logger.warning(f"Unsupported AI provider '{ai_provider}', defaulting to 'openai'")
        ai_provider = 'openai'
    config['ai_provider'] = ai_provider
    
    # Debug AWS configuration if using Bedrock
    if ai_provider == 'aws_bedrock':
        aws_region = os.getenv('AWS_REGION', '').strip()
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID', '').strip()
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '').strip()
        
        logger.info(f"AWS Bedrock configuration check:")
        logger.info(f"  - AWS_REGION: {'✓ Set' if aws_region else '✗ Not set (will default to us-east-1)'}")
        logger.info(f"  - AWS_ACCESS_KEY_ID: {'✓ Set' if aws_access_key else '✗ Not set'}")
        logger.info(f"  - AWS_SECRET_ACCESS_KEY: {'✓ Set' if aws_secret_key else '✗ Not set'}")
        
        if not aws_access_key or not aws_secret_key:
            logger.error("AWS credentials are required for Bedrock but not found in environment")
            logger.error("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY secrets in GitHub Actions")
    
    # Validate scan level
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high').strip().lower()
    if scan_level not in ['critical-high', 'all']:
        logger.warning(f"Invalid scan level '{scan_level}', defaulting to 'critical-high'")
        scan_level = 'critical-high'
    config['scan_level'] = scan_level
    
    # Validate hourly rate (must be positive number)
    try:
        hourly_rate = float(os.getenv('SECURITY_ENGINEER_HOURLY_RATE', '150'))
        if hourly_rate <= 0 or hourly_rate > 1000:  # Reasonable range
            logger.warning(f"Hourly rate {hourly_rate} seems unrealistic, using default $150")
            hourly_rate = 150.0
        config['hourly_rate'] = hourly_rate
    except ValueError:
        logger.warning("Invalid hourly rate format, using default $150")
        config['hourly_rate'] = 150.0
    
    # Validate API keys (check format but don't log values)
    api_keys = ['OPENAI_API_KEY', 'CLAUDE_API_KEY']
    for key_var in api_keys:
        key_value = os.getenv(key_var, '').strip()
        if key_value:
            # Basic format validation without exposing the key
            if len(key_value) < 10:
                logger.warning(f"{key_var} appears too short to be valid")
            elif '\n' in key_value or '\r' in key_value:
                logger.warning(f"{key_var} contains invalid characters")
            else:
                config[key_var.lower()] = True  # Mark as present
        else:
            config[key_var.lower()] = False
    
    # Skip verbose configuration logging for cleaner output
    
    return config

def is_github_actions() -> bool:
    """Check if running in GitHub Actions environment."""
    return os.getenv('GITHUB_ACTIONS') == 'true'

def select_repository() -> str:
    """
    Interactive repository selection for security analysis.
    """
    print("\n📁 Repository Selection:")
    print("   [1] Current directory")
    print("   [2] Browse for directory")
    print("   [3] Enter path manually")

    while True:
        choice = input("\nChoose repository option [1-3]: ").strip()

        if choice == '1':
            repo_path = os.getcwd()
            print(f"Selected: {repo_path}")
            return repo_path

        elif choice == '2':
            print("\nScanning for repositories...")
            repos = []
            seen = set()

            # Get search paths
            user_home = os.path.expanduser("~")
            search_paths = [
                os.getcwd(),  # Current directory
                os.path.join(user_home, "repos"),
                os.path.join(user_home, "projects"),
                os.path.join(user_home, "code"),
                os.path.join(user_home, "workspace"),
                user_home,
            ]

            # Add from environment variable if set
            if os.getenv('REPO_SEARCH_PATHS'):
                search_paths.extend(os.getenv('REPO_SEARCH_PATHS').split(':'))

            # Search for git repos in all paths
            for search_path in search_paths:
                if not os.path.exists(search_path):
                    continue

                try:
                    # Check if the search path itself is a git repo
                    if os.path.exists(os.path.join(search_path, '.git')):
                        real_path = os.path.realpath(search_path)
                        if real_path not in seen:
                            seen.add(real_path)
                            repos.append((Path(search_path).name, search_path))

                    # Look for git repos one level deep
                    for item in os.listdir(search_path):
                        item_path = os.path.join(search_path, item)
                        if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, '.git')):
                            real_path = os.path.realpath(item_path)
                            if real_path not in seen:
                                seen.add(real_path)
                                repos.append((item, item_path))
                except (PermissionError, OSError):
                    continue

            # Sort alphabetically and display
            repos.sort(key=lambda x: x[0].lower())

            if repos:
                for idx, (name, path) in enumerate(repos, 1):
                    # Show relative path if it's shorter
                    try:
                        rel_path = os.path.relpath(path)
                        display_path = rel_path if len(rel_path) < len(path) else path
                    except ValueError:
                        display_path = path
                    print(f"   [{idx}] {name} ({display_path})")

                while True:
                    try:
                        repo_choice = input(f"\nChoose repository [1-{len(repos)}] or 'q' to go back: ").strip()
                        if repo_choice.lower() == 'q':
                            break
                        idx = int(repo_choice) - 1
                        if 0 <= idx < len(repos):
                            repo_path = repos[idx][1]
                            print(f"Selected: {repo_path}")
                            return repo_path
                        else:
                            print(f"Invalid choice. Please enter 1-{len(repos)}")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            else:
                print("No git repositories found in common locations")
                print(f"Searched: {', '.join([p for p in search_paths if os.path.exists(p)])}")
                
        elif choice == '3':
            repo_path = input("\nEnter repository path: ").strip()
            if repo_path and Path(repo_path).exists():
                if Path(repo_path).is_dir():
                    print(f"Selected: {repo_path}")
                    return repo_path
                else:
                    print("❌ Path is not a directory")
            else:
                print("❌ Path does not exist")
        else:
            print("Invalid choice. Please enter 1, 2, or 3")

def run_security_scans(repo_path: str, scanners_to_run: List[str], output_dir: Path, scan_level: str = None) -> List[Dict[str, Any]]:
    """
    Synchronous wrapper for async scanner execution.

    This maintains backward compatibility while using the new async architecture.

    Args:
        repo_path: Path to repository to scan
        scanners_to_run: List of scanners to run
        output_dir: Output directory for results
        scan_level: Scan level ('critical-high' or 'all'), defaults to env var or 'critical-high'
    """
    if scan_level is None:
        scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
    return asyncio.run(run_security_scans_async(repo_path, scanners_to_run, output_dir, scan_level))

async def run_security_scans_async(repo_path: str, scanners_to_run: List[str], output_dir: Path, scan_level: str = 'critical-high') -> List[Dict[str, Any]]:
    """
    Run the selected security scanners AND code quality linters in parallel.

    This function runs multiple scanners concurrently using asyncio for better
    resource management and scalability.

    Args:
        repo_path: Path to repository to scan
        scanners_to_run: List of scanners to run
        output_dir: Output directory for scan results
        scan_level: Scan level ('critical-high' or 'all') - ONLY affects security findings

    Returns:
        list: All findings from all scanners (security + code quality)
    """
    # Ensure output directories exist
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw").mkdir(parents=True, exist_ok=True)

    logger.info(f"🔍 run_security_scans_async - Using scan_level: {scan_level}")

    # Detect languages for code quality scanning (runs in parallel with security scans)
    # Read directly from environment to support runtime changes (CLI/Web tool selection)
    enable_code_quality = os.getenv('APPSEC_CODE_QUALITY', 'true').lower() == 'true'
    detected_languages = set()
    if enable_code_quality:
        try:
            detected_languages = detect_languages(Path(repo_path))
            if detected_languages:
                logger.info(f"📊 Detected languages: {', '.join(sorted(detected_languages))}")
        except Exception as e:
            logger.warning(f"Language detection failed: {e}")

    # Define scanner coroutines with their display names
    scanner_tasks = []

    # Security scanners (always run)
    if "semgrep" in scanners_to_run or "all" in scanners_to_run:
        # Capture scan_level explicitly in lambda to avoid late binding issues
        scanner_tasks.append({
            'name': 'semgrep',
            'display_name': 'Semgrep (SAST)',
            'func': lambda sl=scan_level: run_semgrep(repo_path, str(output_dir / "raw"), sl),
            'category': 'security'
        })

    if "gitleaks" in scanners_to_run or "all" in scanners_to_run:
        scanner_tasks.append({
            'name': 'gitleaks',
            'display_name': 'Gitleaks (Secrets)',
            'func': lambda: run_gitleaks(repo_path, str(output_dir / "raw")),
            'category': 'security'
        })

    if "trivy" in scanners_to_run or "all" in scanners_to_run:
        scanner_tasks.append({
            'name': 'trivy',
            'display_name': 'Trivy (Dependencies)',
            'func': lambda: run_trivy_scan(repo_path, str(output_dir / "raw")),
            'category': 'security'
        })

    # Code quality linters (run based on detected languages)
    if enable_code_quality and detected_languages:
        # JavaScript/TypeScript - ESLint
        if ('javascript' in detected_languages or 'typescript' in detected_languages) and ESLINT_AVAILABLE:
            scanner_tasks.append({
                'name': 'eslint',
                'display_name': 'ESLint (Code Quality)',
                'func': lambda: run_eslint(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added ESLint to scan pipeline")

        # Python - Pylint
        if 'python' in detected_languages and PYLINT_AVAILABLE:
            scanner_tasks.append({
                'name': 'pylint',
                'display_name': 'Pylint (Code Quality)',
                'func': lambda: run_pylint(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added Pylint to scan pipeline")

        # Java - Checkstyle
        if 'java' in detected_languages and CHECKSTYLE_AVAILABLE:
            scanner_tasks.append({
                'name': 'checkstyle',
                'display_name': 'Checkstyle (Code Quality)',
                'func': lambda: run_checkstyle(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added Checkstyle to scan pipeline")

        # Go - golangci-lint
        if 'go' in detected_languages and GOLANGCI_AVAILABLE:
            scanner_tasks.append({
                'name': 'golangci-lint',
                'display_name': 'golangci-lint (Code Quality)',
                'func': lambda: run_golangci_lint(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added golangci-lint to scan pipeline")

        # Ruby - RuboCop
        if 'ruby' in detected_languages and RUBOCOP_AVAILABLE:
            scanner_tasks.append({
                'name': 'rubocop',
                'display_name': 'RuboCop (Code Quality)',
                'func': lambda: run_rubocop(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added RuboCop to scan pipeline")

        # Rust - Clippy
        if 'rust' in detected_languages and CLIPPY_AVAILABLE:
            scanner_tasks.append({
                'name': 'clippy',
                'display_name': 'Clippy (Code Quality)',
                'func': lambda: run_clippy(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added Clippy to scan pipeline")

        # PHP - PHPStan
        if 'php' in detected_languages and PHPSTAN_AVAILABLE:
            scanner_tasks.append({
                'name': 'phpstan',
                'display_name': 'PHPStan (Code Quality)',
                'func': lambda: run_phpstan(repo_path, str(output_dir / "raw")),
                'category': 'code_quality'
            })
            logger.debug("Added PHPStan to scan pipeline")

    if not scanner_tasks:
        print("No scanners selected")
        return []

    # Count security vs code quality scanners
    security_count = sum(1 for t in scanner_tasks if t.get('category') == 'security')
    quality_count = sum(1 for t in scanner_tasks if t.get('category') == 'code_quality')

    print(f"🔍 Starting scan ({security_count} security + {quality_count} code quality scanners)...")
    start_time = time.time()

    # Run all scanner functions concurrently
    results = await asyncio.gather(*[
        asyncio.to_thread(task['func']) for task in scanner_tasks
    ], return_exceptions=True)

    # Process results
    all_findings = []
    security_findings_count = 0
    code_quality_findings_count = 0

    for i, result in enumerate(results):
        task = scanner_tasks[i]
        if isinstance(result, Exception):
            print(f"❌ {task['display_name']} failed: {result}")
        else:
            findings = result if result else []
            # Add tool identifier to findings
            for finding in findings:
                finding['tool'] = task['name']
            all_findings.extend(findings)

            # Track separately for reporting
            if task.get('category') == 'code_quality':
                code_quality_findings_count += len(findings)
                if len(findings) > 0:
                    print(f"✅ {task['display_name']}: {len(findings)} code quality issues")
                elif len(findings) == 0 and not isinstance(result, Exception):
                    print(f"✅ {task['display_name']}: clean (no issues found)")
            else:
                security_findings_count += len(findings)
                if len(findings) > 0:
                    print(f"✅ {task['display_name']}: {len(findings)} vulnerabilities")
                else:
                    print(f"✅ {task['display_name']}: no issues")

    elapsed_time = time.time() - start_time

    # Summary message
    if code_quality_findings_count > 0:
        print(f"🎯 Scan complete: {security_findings_count} security issues + {code_quality_findings_count} code quality issues in {elapsed_time:.1f}s")
    else:
        print(f"🎯 Scan complete: {security_findings_count} vulnerabilities found in {elapsed_time:.1f}s")

    return all_findings

def run_auto_mode() -> List[Dict[str, Any]]:
    """Run scanner in automatic mode (GitHub Actions)."""
    # Validate environment configuration first
    try:
        env_config = validate_environment_config()
    except Exception as e:
        logger.error(f"Environment configuration validation failed: {e}")
        return []

    # Determine repo path based on how scanner is deployed
    if is_github_actions():
        # Check if we're running as a GitHub Action (external) or copied files (internal)
        workspace = os.getenv('GITHUB_WORKSPACE', '')
        current_dir = os.getcwd()

        # If GITHUB_WORKSPACE differs from current directory, we're running as external action
        if workspace and workspace != current_dir and Path(workspace).exists():
            repo_path = validate_repo_path(workspace)
            print(f"🔧 Running as GitHub Action - scanning external repo: {workspace}")
        else:
            # We're running from copied files within the target repo
            repo_path = validate_repo_path(current_dir)
            print(f"🔧 Running from copied files - scanning current directory: {current_dir}")
    else:
        # Use current directory as repo path for local interactive runs
        repo_path = validate_repo_path(os.getcwd())

    # Set up output directory with new repo/branch structure
    output_path = get_output_path(str(repo_path), BASE_OUTPUT_DIR)

    # Clean up old scans (keep only most recent)
    cleanup_old_scans(output_path)

    # Set up directory structure
    output_dirs = setup_output_directories(output_path)
    output_dir = output_dirs['base']
    
    # Run all scanners
    scanners_to_run = ["semgrep", "gitleaks", "trivy"]
    
    print(f"🔒 AppSec-Sentinel - Auto Mode")
    print(f"📁 Scanning: {repo_path}")
    print(f"📁 Output: {output_dir}")
    print(f"🔍 Scanners: {', '.join(scanners_to_run)}")
    
    # Debug info for troubleshooting CI issues
    if is_github_actions():
        print(f"🔧 Debug: Current working directory: {os.getcwd()}")
        print(f"🔧 Debug: GITHUB_WORKSPACE: {os.getenv('GITHUB_WORKSPACE', 'not set')}")

    # Get scan level from environment for CI/CD consistency
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
    print(f"🔍 Scan level: {scan_level}")

    # Run scanners in parallel
    all_findings = run_security_scans(str(repo_path), scanners_to_run, output_dir, scan_level)
    
    # Generate reports with cross-file enhancement (same as interactive mode)
    if all_findings:
        print(f"\n📊 Found {len(all_findings)} security findings")
        
        # Enhance findings with cross-file analysis (same as interactive mode)
        enhanced_findings = all_findings
        context_summary = ""
        
        if CROSS_FILE_AVAILABLE and all_findings:
            print("🧠 Running cross-file enhancement analysis...")
            try:
                from enhanced_analyzer import enhance_findings_with_cross_file
                enhanced_findings = asyncio.run(enhance_findings_with_cross_file(all_findings, str(repo_path)))
                
                # Context will be shown in the detailed section
                context_summary = ""
                
                print(f"✅ Enhanced {len(enhanced_findings)} findings with cross-file analysis")
            except Exception as e:
                logger.warning(f"Cross-file enhancement failed, using standard analysis: {e}")
                enhanced_findings = all_findings
        
        # Generate HTML report
        try:
            # Generate AI summary with cross-file insights
            if enhanced_findings:
                # Separate security from code quality findings
                security_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
                code_quality_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

                summary_stats = {
                    'total_security': len(security_findings),
                    'total_code_quality': len(code_quality_findings),
                    'critical': len([f for f in security_findings if f.get('severity', '').lower() == 'critical']),
                    'high': len([f for f in security_findings if f.get('severity', '').lower() in ['high', 'error']]),
                    'sast': len([f for f in security_findings if f.get('tool') == 'semgrep']),
                    'secrets': len([f for f in security_findings if f.get('tool') == 'gitleaks']),
                    'deps': len([f for f in security_findings if f.get('tool') == 'trivy'])
                }

                # Build security findings section
                security_breakdown = f"""**Security Issues ({summary_stats['total_security']} total):**
• {summary_stats['critical']} critical vulnerabilities requiring immediate attention
• {summary_stats['high']} high-severity issues needing prompt remediation
• {summary_stats['sast']} code security issues (SAST)
• {summary_stats['secrets']} secrets detected in repository
• {summary_stats['deps']} vulnerable dependencies identified"""

                # Add code quality section if present
                code_quality_section = ""
                if summary_stats['total_code_quality'] > 0:
                    code_quality_section = f"""

**Code Quality Issues ({summary_stats['total_code_quality']} total):**
• Maintainability, complexity, and best practice violations
• Always shown regardless of security scan level"""

                ai_summary = f"""🛡️ Security Analysis Complete

**Risk Assessment:** {'🔴 High Risk' if summary_stats['critical'] > 0 else '🟡 Medium Risk' if summary_stats['high'] > 0 else '🟢 Low Risk'}

{security_breakdown}{code_quality_section}{context_summary}

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""
            else:
                ai_summary = "🎉 Security scan completed successfully with no critical or high-severity issues found."
                
            generate_html_report(enhanced_findings, ai_summary, str(output_dir), str(repo_path), detect_languages(Path(repo_path)))
            html_report_path = output_dir / "report.html"
            print(f"📄 HTML report generated: {html_report_path}")
        except Exception as e:
            print(f"⚠️  HTML report generation failed: {e}")
            logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        
        # Generate cross-file enhanced reports if available
        if CROSS_FILE_AVAILABLE and enhanced_findings:
            try:
                from enhanced_analyzer import generate_cross_file_enhanced_report
                enhanced_report = asyncio.run(generate_cross_file_enhanced_report(enhanced_findings, str(repo_path)))
                
                # Create PR findings summary
                pr_summary_path = output_dir / "pr-findings.txt"
                
                with open(pr_summary_path, 'w') as f:
                    f.write(enhanced_report.get('pr_summary', 'No PR summary available'))
                
                print(f"📄 cross-file enhanced PR summary: {pr_summary_path}")
            except Exception as e:
                logger.warning(f"cross-file report generation failed: {e}")
        
        # Auto-generate SBOM as part of security scan (same as interactive mode)
        if SBOM_AVAILABLE:
            print("📋 Auto-generating SBOM for compliance...")
            try:
                asyncio.run(generate_repository_sbom(str(repo_path), str(output_dir / "sbom")))
                print("✅ SBOM generated in outputs/sbom/")
            except Exception as e:
                logger.warning(f"SBOM generation failed: {e}")
                print("⚠️ SBOM generation failed (scan continues)")
        else:
            print("⚠️ SBOM generation requires Syft (scan continues without SBOM)")
        
        # Run auto-remediation with enhanced findings
        handle_auto_remediation(str(repo_path), enhanced_findings)
    else:
        print("🎉 No security issues found!")
        
        # Generate SBOM even when no vulnerabilities are found
        if SBOM_AVAILABLE:
            print("📋 Auto-generating SBOM for compliance...")
            try:
                asyncio.run(generate_repository_sbom(str(repo_path), str(output_dir / "sbom")))
                print("✅ SBOM generated in outputs/sbom/")
            except Exception as e:
                logger.warning(f"SBOM generation failed: {e}")
                print("⚠️ SBOM generation failed")
    
    return enhanced_findings

# Cross-File Integration for enhanced AI analysis
try:
    from enhanced_analyzer import enhance_findings_with_cross_file, generate_cross_file_enhanced_report
    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False

# SBOM and Tool Ingestion
try:
    from sbom_generator import generate_repository_sbom
    from tool_ingestion import ingest_project_tools
    SBOM_AVAILABLE = True
    TOOL_INGESTION_AVAILABLE = True
except ImportError:
    SBOM_AVAILABLE = False
    TOOL_INGESTION_AVAILABLE = False


def show_interactive_menu() -> str:
    """Show interactive menu and return user choice"""
    print("🎯 Choose an option:")
    print("   [1] Security scan with auto-fixes + SBOM")
    print("   [2] Enhance project tool results")
    print("   [q] Quit")

    while True:
        choice = input("\nEnter your choice [1-2, q]: ").strip().lower()
        if choice in ['1', '2', 'q']:
            return choice
        print("Invalid choice. Please enter 1, 2, or q")

def select_scan_level() -> str:
    """Let user choose severity level for scanning"""
    print("\n🔍 Select severity level:")
    print("   [1] Critical & High only (Recommended - fewer false positives)")
    print("   [2] All severity levels (More findings, may include noise)")

    while True:
        choice = input("\nChoose severity level [1-2]: ").strip()
        if choice == '1':
            return 'critical-high'
        elif choice == '2':
            return 'all'
        else:
            print("Invalid choice. Please enter 1 or 2")

def select_tools() -> set:
    """Let user choose which tools to run"""
    print("\n🔧 Select tools to run:")
    print("   [1] All (comprehensive scan)")
    print("   [2] Security only (semgrep + gitleaks + trivy)")
    print("   [3] SAST only (semgrep)")
    print("   [4] Secrets only (gitleaks)")
    print("   [5] Dependencies only (trivy)")
    print("   [6] Custom selection...")

    while True:
        choice = input("\nChoose tool selection [1-6]: ").strip()

        if choice == '1':
            return {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}
        elif choice == '2':
            return {'semgrep', 'trivy', 'gitleaks', 'sbom'}
        elif choice == '3':
            return {'semgrep', 'code_quality', 'sbom'}
        elif choice == '4':
            return {'gitleaks', 'sbom'}
        elif choice == '5':
            return {'trivy', 'sbom'}
        elif choice == '6':
            # Custom selection with checkboxes
            print("\n📋 Select individual tools (y/n):")
            tools = set()

            if input("   Run Semgrep (SAST)? [Y/n]: ").strip().lower() != 'n':
                tools.add('semgrep')

            if input("   Run Trivy (Dependencies/SCA)? [Y/n]: ").strip().lower() != 'n':
                tools.add('trivy')

            if input("   Run Gitleaks (Secrets)? [Y/n]: ").strip().lower() != 'n':
                tools.add('gitleaks')

            if input("   Run Code Quality linters? [Y/n]: ").strip().lower() != 'n':
                tools.add('code_quality')

            if input("   Generate SBOM? [Y/n]: ").strip().lower() != 'n':
                tools.add('sbom')

            if not tools:
                print("❌ No tools selected. Please select at least one tool.")
                continue

            # Display selection
            print(f"\n✅ Selected tools: {', '.join(sorted(tools))}")
            return tools
        else:
            print("Invalid choice. Please enter 1-6")

def handle_auto_remediation(repo_path: str, all_findings: List[Dict[str, Any]], auto_choice: Optional[int] = None) -> dict:
    """Handle auto-remediation flow for findings"""
    total_findings = len(all_findings)
    critical_findings = len([f for f in all_findings if f.get('severity', '').lower() in ['critical']])
    high_findings = len([f for f in all_findings if f.get('severity', '').lower() in ['high', 'error']])
    
    print(f"\n📊 Scan Results:")
    print(f"   • Total findings: {total_findings}")
    print(f"   • Critical: {critical_findings}")
    print(f"   • High: {high_findings}")
    
    if total_findings == 0:
        print("🎉 No security issues found! Your code looks clean.")
        return {"success": True, "message": "No vulnerabilities found"}
    
    # Check for auto-fixable findings
    sast_findings = [f for f in all_findings if f.get('tool') in ['semgrep', 'gitleaks']]
    dependency_findings = [f for f in all_findings if f.get('tool') == 'trivy' and f.get('fixed_version')]
    secrets_count = len([f for f in all_findings if f.get('tool') == 'gitleaks'])
    semgrep_count = len([f for f in all_findings if f.get('tool') == 'semgrep'])
    
    # Debug: Trace finding counts for CI/CD vs CLI discrepancy investigation
    env_type = "CI/CD" if is_github_actions() else "CLI"
    logger.debug(f"[{env_type}] Repository path: {repo_path}")
    logger.debug(f"[{env_type}] Working directory: {os.getcwd()}")
    logger.debug(f"[{env_type}] Finding counts - Total: {len(all_findings)}, Semgrep: {semgrep_count}, Secrets: {secrets_count}")
    
    # Debug: Show breakdown of Semgrep findings by severity
    semgrep_findings_by_severity = {}
    for finding in [f for f in all_findings if f.get('tool') == 'semgrep']:
        severity = finding.get('severity', 'unknown')
        semgrep_findings_by_severity[severity] = semgrep_findings_by_severity.get(severity, 0) + 1
    logger.debug(f"[{env_type}] Semgrep severity breakdown: {semgrep_findings_by_severity}")
    
    # Debug: Log all Semgrep check_ids for comparison
    semgrep_check_ids = [f.get('check_id', 'unknown') for f in all_findings if f.get('tool') == 'semgrep']
    logger.debug(f"[{env_type}] Semgrep check_ids found: {semgrep_check_ids[:5]}...")  # Show first 5
    
    if sast_findings or dependency_findings:
        print(f"\n🔧 Auto-Remediation Options:")
        if sast_findings:
            if semgrep_count > 0 and secrets_count > 0:
                print(f"   Found {semgrep_count} SAST vulnerabilities (auto-fixable) + {secrets_count} secrets (manual review required)")
            elif semgrep_count > 0:
                print(f"   Found {semgrep_count} SAST vulnerabilities that might be auto-fixable")
            elif secrets_count > 0:
                print(f"   Found {secrets_count} secrets detected (manual review required)")
        total_deps = len([f for f in all_findings if f.get('tool') == 'trivy'])
        if dependency_findings:
            print(f"   Found {len(dependency_findings)} auto-fixable dependency vulnerabilities ({total_deps} total dependencies)")
        if sast_findings and dependency_findings:
            print("   [1] Auto-fix code issues (SAST) + flag secrets")
            print("   [2] Auto-fix dependencies only") 
            print("   [3] Auto-fix both (creates 2 separate PRs)")
            print("   [4] Skip auto-fix")
        elif sast_findings:
            print("   [1] Auto-fix code issues (SAST) + flag secrets")
            print("   [4] Skip auto-fix")
        elif dependency_findings:
            print("   [2] Auto-fix dependencies only")
            print("   [4] Skip auto-fix")
        
        # Handle automated mode (when auto_choice parameter is provided)
        if auto_choice is not None:
            choice = str(auto_choice)
            print(f"🤖 Automated mode: Using option {choice}")
        # Handle CI/CD and Web environments automatically
        elif is_github_actions() or os.getenv('APPSEC_WEB_MODE', 'false').lower() == 'true':
            # In CI environments, determine auto-fix behavior from environment variables
            auto_fix_enabled = os.getenv('APPSEC_AUTO_FIX', 'false').lower() == 'true'
            auto_fix_mode = os.getenv('APPSEC_AUTO_FIX_MODE', '')  # Optional specific mode override
            
            if auto_fix_mode in ['1', '2', '3', '4']:
                # Validate the mode makes sense given available findings
                if auto_fix_mode == '2' and not dependency_findings:
                    # User wants dependency-only fix but no dependencies found
                    choice = '1' if sast_findings else '4'
                    print(f"   → Adjusting mode: No dependencies found, using mode {choice}")
                elif auto_fix_mode == '3' and not dependency_findings:
                    # User wants both but no dependencies found
                    choice = '1' if sast_findings else '4'  
                    print(f"   → Adjusting mode: No dependencies found, using mode {choice} (SAST only)")
                elif auto_fix_mode == '3' and not sast_findings:
                    # User wants both but no SAST findings found
                    choice = '2' if dependency_findings else '4'
                    print(f"   → Adjusting mode: No SAST findings found, using mode {choice}")
                else:
                    choice = auto_fix_mode
            elif auto_fix_enabled:
                # If auto-fix is enabled but no specific mode, choose based on what's available
                if sast_findings and dependency_findings:
                    choice = '3'  # Auto-fix both
                elif sast_findings:
                    choice = '1'  # Auto-fix SAST only
                elif dependency_findings:
                    choice = '2'  # Auto-fix dependencies only
                else:
                    choice = '4'  # Nothing to auto-fix
            else:
                choice = '4'  # Auto-fix disabled
                
            env_type = "CI Environment" if is_github_actions() else "Web Interface"
            print(f"🤖 {env_type} detected - using auto-fix mode: {choice}")
            if choice == '1':
                print("   → Auto-fixing code issues (SAST) + flagging secrets")
            elif choice == '2':
                print("   → Auto-fixing dependencies only")
            elif choice == '3':
                print("   → Auto-fixing both (creates 2 separate PRs)")
            else:
                print("   → Skipping auto-fix")
        else:
            # Interactive mode for local development
            while True:
                choice = input("\nChoose auto-fix option [1-4]: ").strip()
                if choice in ['1', '2', '3', '4']:
                    break
                print("Invalid choice. Please enter 1, 2, 3, or 4")
        
        # Execute auto-remediation
        if choice != '4':
            from auto_remediation.remediation import create_remediation_pr
            
            try:
                sast_success = True
                dep_success = True
                
                if choice in ['1', '3'] and sast_findings:
                    if semgrep_count > 0 and secrets_count > 0:
                        print(f"🔧 Creating code security PR (SAST fixes + secret flagging)...")
                    elif semgrep_count > 0:
                        print(f"🔧 Creating SAST auto-fix PR...")
                    else:
                        print(f"🔧 Creating secrets detection PR (manual review required)...")
                    sast_success = create_remediation_pr(repo_path, sast_findings, "sast")
                
                if choice in ['2', '3'] and dependency_findings:
                    print(f"🔧 Creating dependency auto-fix PR...")
                    dep_success = create_remediation_pr(repo_path, dependency_findings, "dependencies")
                
                if sast_success and dep_success:
                    print("\n✅ Auto-remediation complete!")
                    return {"success": True, "message": "Auto-remediation completed successfully"}
                else:
                    print("\n⚠️ Auto-remediation completed with issues (check errors above)")
                    return {"success": False, "message": "Auto-remediation had issues - check logs"}
                
            except Exception as e:
                print(f"\n❌ Auto-remediation failed: {e}")
                return {"success": False, "message": f"Auto-remediation failed: {e}"}
    else:
        print("\n💡 No auto-fixable vulnerabilities found in this scan.")
        return {"success": True, "message": "No auto-fixable vulnerabilities found"}

def track_usage() -> None:
    """
    Track usage analytics for IP monitoring while repository is public.
    Logs essential usage metrics without exposing sensitive information.
    """
    try:
        import platform
        import getpass
        from datetime import datetime
        
        # Collect basic usage metrics (no sensitive data)
        usage_data = {
            'timestamp': datetime.now(datetime.UTC).isoformat(),
            'version': '1.3.0',
            'mode': 'CI/CD' if is_github_actions() else 'CLI',
            'platform': platform.system(),
            'user_id': getpass.getuser()[:8] + "***",  # Partially anonymized
            'scan_level': os.getenv('APPSEC_SCAN_LEVEL', 'critical-high'),
            'auto_fix_enabled': os.getenv('APPSEC_AUTO_FIX', 'false') == 'true'
        }
        
        # Log usage for monitoring (no external transmission)
        logger.info(f"📊 Usage Analytics: {json.dumps(usage_data, indent=2)}")
        
        # Store usage log locally for IP monitoring
        usage_log_dir = Path("outputs/analytics")
        usage_log_dir.mkdir(parents=True, exist_ok=True)
        
        usage_file = usage_log_dir / f"usage_{datetime.now().strftime('%Y%m%d')}.json"
        
        # Append to daily usage log
        existing_logs = []
        if usage_file.exists():
            try:
                with open(usage_file, 'r') as f:
                    existing_logs = json.load(f)
            except Exception:
                existing_logs = []
        
        existing_logs.append(usage_data)
        
        with open(usage_file, 'w') as f:
            json.dump(existing_logs, f, indent=2)
            
        logger.debug(f"Usage tracked to {usage_file}")
        
    except Exception as e:
        logger.debug(f"Usage tracking failed (non-critical): {e}")

def main() -> None:
    """
    Main entry point - Interactive security analysis for consultants.
    """
    import sys
    
    # Track usage for IP monitoring
    track_usage()
    
    # Enable debug mode if requested
    if os.getenv('APPSEC_DEBUG', 'false').lower() == 'true':
        set_debug_mode(True)
        logger.debug("AppSec-Sentinel starting in debug mode")
    
    # Environment detection for debugging CI/CD vs CLI differences
    env_type = "CI/CD" if is_github_actions() else "CLI"
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
    logger.info(f"Starting AppSec-Sentinel - Mode: {env_type}, Scan Level: {scan_level}")
    
    # Debug: Log environment variables that might affect scanning
    debug_env_vars = ['APPSEC_SCAN_LEVEL', 'APPSEC_AUTO_FIX', 'APPSEC_AUTO_FIX_MODE', 'GITHUB_ACTIONS']
    logger.debug(f"Environment variables: {[(var, os.getenv(var, 'not_set')) for var in debug_env_vars]}")
    
    # Check if running in GitHub Actions (for project CI/CD)
    if is_github_actions():
        return run_auto_mode()

    # Otherwise run interactive mode (CLI or Web)
    print("\n" + "="*80)
    print("🔒 AppSec-Sentinel - © 2025 Open Source Security Scanner")
    print("="*80)
    print("AI-powered security scanner that finds vulnerabilities and creates fixes")
    print("📖 MIT Licensed - Free for personal and commercial use")
    print("="*80)
    print()
    
    try:
        # Show menu and get user choice
        choice = show_interactive_menu()
        
        if choice == 'q':
            print("👋 Goodbye!")
            return
        
        # Execute based on choice
        if choice == '1':
            # Security scan with auto-fixes (needs repo selection)
            repo_path = select_repository()
            if not repo_path:
                return

            # Set up output directory with new repo/branch structure
            output_path = get_output_path(repo_path, BASE_OUTPUT_DIR)

            # Clean up old scans (keep only most recent)
            cleanup_old_scans(output_path)

            # Set up directory structure
            output_dirs = setup_output_directories(output_path)
            output_dir = output_dirs['base']

            print(f"📁 Output directory: {output_dir}")

            # Let user choose tools to run
            selected_tools = select_tools()

            # Let user choose severity level
            scan_level = select_scan_level()

            # Convert tool selection to scanner list (security scanners only)
            scanners_to_run = []
            if 'semgrep' in selected_tools:
                scanners_to_run.append('semgrep')
            if 'gitleaks' in selected_tools:
                scanners_to_run.append('gitleaks')
            if 'trivy' in selected_tools:
                scanners_to_run.append('trivy')

            # Code quality and SBOM are handled separately
            run_code_quality = 'code_quality' in selected_tools
            run_sbom = 'sbom' in selected_tools

            # Temporarily override APPSEC_CODE_QUALITY for this scan (with proper cleanup)
            original_code_quality = os.getenv('APPSEC_CODE_QUALITY')
            try:
                os.environ['APPSEC_CODE_QUALITY'] = 'true' if run_code_quality else 'false'

                print(f"\n🔍 Running security scan (level: {scan_level})...")
                all_findings = run_security_scans(repo_path, scanners_to_run, output_dir, scan_level)
            finally:
                # Restore original code quality setting (always runs, even on exception)
                if original_code_quality is not None:
                    os.environ['APPSEC_CODE_QUALITY'] = original_code_quality
                else:
                    os.environ.pop('APPSEC_CODE_QUALITY', None)
            
            # Generate reports with cross-file enhancement
            try:
                print("📊 Generating reports...")
                
                # Enhance findings with cross-file analysis first
                enhanced_findings = all_findings
                context_summary = ""
                
                if CROSS_FILE_AVAILABLE and all_findings:
                    print("🧠 Running cross-file enhancement analysis...")
                    try:
                        from enhanced_analyzer import enhance_findings_with_cross_file
                        enhanced_findings = asyncio.run(enhance_findings_with_cross_file(all_findings, repo_path))
                        
                        # Context will be shown in the detailed section instead
                        context_summary = ""  # Remove from AI summary
                        
                        print(f"✅ Enhanced {len(enhanced_findings)} findings with cross-file analysis")
                    except Exception as e:
                        logger.warning(f"Cross-file enhancement failed, using standard analysis: {e}")
                        enhanced_findings = all_findings
                
                # Generate AI summary with cross-file insights
                if enhanced_findings:
                    # Separate security from code quality findings
                    security_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
                    code_quality_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

                    summary_stats = {
                        'total_security': len(security_findings),
                        'total_code_quality': len(code_quality_findings),
                        'critical': len([f for f in security_findings if f.get('severity', '').lower() == 'critical']),
                        'high': len([f for f in security_findings if f.get('severity', '').lower() in ['high', 'error']]),
                        'sast': len([f for f in security_findings if f.get('tool') == 'semgrep']),
                        'secrets': len([f for f in security_findings if f.get('tool') == 'gitleaks']),
                        'deps': len([f for f in security_findings if f.get('tool') == 'trivy'])
                    }

                    # Build security findings section
                    security_breakdown = f"""**Security Issues ({summary_stats['total_security']} total):**
• {summary_stats['critical']} critical vulnerabilities requiring immediate attention
• {summary_stats['high']} high-severity issues needing prompt remediation
• {summary_stats['sast']} code security issues (SAST)
• {summary_stats['secrets']} secrets detected in repository
• {summary_stats['deps']} vulnerable dependencies identified"""

                    # Add code quality section if present
                    code_quality_section = ""
                    if summary_stats['total_code_quality'] > 0:
                        code_quality_section = f"""

**Code Quality Issues ({summary_stats['total_code_quality']} total):**
• Maintainability, complexity, and best practice violations
• Always shown regardless of security scan level"""

                    ai_summary = f"""🛡️ Security Analysis Complete

**Risk Assessment:** {'🔴 High Risk' if summary_stats['critical'] > 0 else '🟡 Medium Risk' if summary_stats['high'] > 0 else '🟢 Low Risk'}

{security_breakdown}{code_quality_section}{context_summary}

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""
                else:
                    ai_summary = "🎉 Security scan completed successfully with no critical or high-severity issues found."
                    
                try:
                    generate_html_report(enhanced_findings, ai_summary, str(output_dir), str(repo_path), detect_languages(Path(repo_path)))
                    html_report_path = output_dir / "report.html"
                    print(f"📄 HTML report: {html_report_path}")
                except Exception as report_error:
                    print(f"⚠️  HTML report generation failed: {report_error}")
                    logger.error(f"HTML report error: {report_error}", exc_info=True)

                # Generate cross-file enhanced reports if available
                if CROSS_FILE_AVAILABLE and enhanced_findings:
                    try:
                        from enhanced_analyzer import generate_cross_file_enhanced_report
                        enhanced_report = asyncio.run(generate_cross_file_enhanced_report(enhanced_findings, repo_path))

                        # Create PR findings summary
                        pr_summary_path = output_dir / "pr-findings.txt"

                        with open(pr_summary_path, 'w') as f:
                            f.write(enhanced_report.get('pr_summary', 'No PR summary available'))

                        print(f"📄 cross-file enhanced PR summary: {pr_summary_path}")
                    except Exception as e:
                        logger.warning(f"cross-file report generation failed: {e}")
            except Exception as e:
                print(f"⚠️  Report generation failed: {e}")
                logger.error(f"Report generation error: {e}", exc_info=True)
            
            # Generate SBOM if user selected it
            if run_sbom and SBOM_AVAILABLE:
                print("📋 Generating SBOM for compliance...")
                try:
                    asyncio.run(generate_repository_sbom(repo_path, str(output_dir / "sbom")))
                    print("✅ SBOM generated in outputs/sbom/")
                except Exception as e:
                    logger.warning(f"SBOM generation failed: {e}")
                    print("⚠️ SBOM generation failed (scan continues)")
            elif run_sbom and not SBOM_AVAILABLE:
                print("⚠️ SBOM generation requires Syft but it's not installed")

            # Handle auto-remediation for findings
            logger.info("🔧 Starting handle_auto_remediation from main choice 1")
            handle_auto_remediation(repo_path, enhanced_findings)
            logger.info("✅ Completed handle_auto_remediation from main choice 1")

        elif choice == '2':
            # Enhance project tool results (works on current directory exports)
            if TOOL_INGESTION_AVAILABLE:
                if Path("projects/project_exports").exists():
                    print("🔄 Enhancing project tool results...")
                    asyncio.run(ingest_project_tools())
                    print("✅ Enhanced results available in outputs/")
                else:
                    print("❌ No projects/project_exports/ directory found. Place tool exports there first.")
            else:
                print("❌ Tool ingestion not available")
            
    except KeyboardInterrupt:
        print("\n\n👋 Scan cancelled by user")
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)

# Standard Python entry point
if __name__ == "__main__":
    main()