"""
Configuration constants for AppSec AI Scanner

These are truly hardcoded values that should be constants.
User-configurable settings should remain in .env file.
"""

# Tool installation URLs (used in error messages)
TOOL_INSTALL_URLS = {
    'semgrep': "pip install semgrep",
    'gitleaks': "https://github.com/gitleaks/gitleaks#installing", 
    'trivy': "https://trivy.dev/getting-started/installation/"
}

# Repository discovery settings
MAX_REPO_SEARCH_DEPTH = 2

# Pipeline safety - files that should never be modified
PROTECTED_FILE_PATTERNS = [
    # CI/CD Pipeline files
    '.github/workflows/',
    '.github/actions/',
    'action.yml',
    'action.yaml',
    '.gitlab-ci.yml',     # GitLab CI
    'azure-pipelines.yml', # Azure DevOps
    'bitbucket-pipelines.yml', # Bitbucket
    'jenkinsfile',        # Jenkins (case insensitive match)
    'Jenkinsfile',        # Jenkins
    '.circleci/',         # CircleCI
    '.buildkite/',        # Buildkite
    'appveyor.yml',       # AppVeyor
    '.travis.yml',        # Travis CI
    
    # Docker ignore and build context files (not security-related)
    '.dockerignore',      # Docker ignore patterns (build context)
    
    # Kubernetes and orchestration
    'k8s/',              # Kubernetes manifests
    'kubernetes/',       # Kubernetes manifests
    'helm/',             # Helm charts
    '.helm/',            # Helm configuration
    
    # Infrastructure as Code
    'terraform/',        # Terraform configurations
    'infrastructure/',   # Common IaC directory
    'cloudformation/',   # AWS CloudFormation
    'pulumi/',          # Pulumi IaC
    
    # Scanner output directories
    'outputs/',           # Don't modify scanner output files
    'outputs/sbom/',      # Don't modify SBOM files
    'outputs/raw/',       # Don't modify raw scan results
    'outputs/reports/'    # Don't modify generated reports
]

# Files/directories to exclude from security scanning
SCAN_EXCLUDE_PATTERNS = [
    'outputs/',           # Scanner output directory
    '.git/',              # Git metadata
    'node_modules/',      # Node.js dependencies
    '__pycache__/',       # Python cache
    '.venv/',             # Python virtual environment
    'venv/',              # Python virtual environment
    'dist/',              # Build outputs
    'build/',             # Build outputs
    '.cache/',            # Various cache directories
]

# Dependency file patterns for scanning
DEPENDENCY_FILE_PATTERNS = [
    "package.json", "package-lock.json", "yarn.lock",        # Node.js
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",  # Python
    "go.mod", "go.sum",                                      # Go
    "Cargo.toml", "Cargo.lock",                             # Rust
    "composer.json", "composer.lock",                       # PHP
    "pom.xml", "build.gradle"                               # Java
]

# Default values (fallbacks when env vars not set)
DEFAULT_MANUAL_REVIEW_TIME = 0.5  # hours per finding
DEFAULT_TOOL_CHECK_TIMEOUT = 10   # seconds

# Git-aware scanning settings
ENABLE_GIT_AWARE_SCANNING = True  # Can be disabled via env var
MAX_CHANGED_FILES_FOR_FULL_SCAN = 100  # If more files changed, do full scan
GIT_DIFF_CONTEXT_LINES = 3  # Lines of context around changes

# Code Quality Scanning (ON by default for maximum value)
# When enabled, language-specific linters will run for code quality
# Set APPSEC_CODE_QUALITY=false to disable
import os
ENABLE_CODE_QUALITY = os.getenv('APPSEC_CODE_QUALITY', 'true').lower() == 'true'

# Tool Selection (CLI/Web only - MCP and CI/CD always run all)
# Parse APPSEC_TOOLS environment variable
# Format: comma-separated list (e.g., "semgrep,gitleaks,trivy")
# Valid options: semgrep, trivy, gitleaks, code_quality, sbom, all
def parse_tool_selection(tools_string: str = None) -> set:
    """
    Parse and validate tool selection from environment or parameter.

    Args:
        tools_string: Comma-separated tool names, defaults to APPSEC_TOOLS env var

    Returns:
        set: Set of validated tool names
    """
    if tools_string is None:
        tools_string = os.getenv('APPSEC_TOOLS', 'all')

    # Normalize and split
    tools_string = tools_string.lower().strip()

    # If 'all', return all tools
    if tools_string == 'all':
        return {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}

    # Parse individual tools
    tools = set()
    valid_tools = {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}

    for tool in tools_string.split(','):
        tool = tool.strip()
        if tool in valid_tools:
            tools.add(tool)
        elif tool:  # Only warn if non-empty
            import logging
            logging.warning(f"Invalid tool '{tool}' ignored. Valid options: {', '.join(sorted(valid_tools))}")

    # Ensure at least one tool is selected
    if not tools:
        import logging
        logging.warning("No valid tools selected, defaulting to 'all'")
        return {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}

    return tools

# Default tool selection for current session
SELECTED_TOOLS = parse_tool_selection()

# AI Temperature for fix generation
# 0.0 = fully deterministic (same input always gives same output)
# 0.1 = slight variation, 1.0 = very creative (not recommended)
AI_TEMPERATURE = float(os.getenv('APPSEC_AI_TEMPERATURE', '0.0'))

# Output path management
# Use absolute path from project root to avoid src/outputs vs outputs confusion
import sys
from pathlib import Path as ConfigPath
_PROJECT_ROOT = ConfigPath(__file__).parent.parent.resolve()  # Go up from src/ to project root
BASE_OUTPUT_DIR = str(_PROJECT_ROOT / "outputs")  # Base directory for all scan results

def format_subprocess_error(tool_name: str, returncode: int, stderr: str, stdout: str = "") -> str:
    """
    Format subprocess errors with helpful context and troubleshooting tips.
    
    Args:
        tool_name: Name of the tool that failed
        returncode: Process return code
        stderr: Standard error output
        stdout: Standard output (optional)
        
    Returns:
        str: Formatted error message with troubleshooting guidance
    """
    error_msg = f"\n❌ {tool_name.capitalize()} failed (exit code {returncode})"
    
    # Add tool-specific troubleshooting
    troubleshooting = {
        'semgrep': {
            'common_issues': [
                "Large repository (try excluding node_modules, .git, etc.)",
                "Network issues downloading rules",
                "Insufficient memory for large files"
            ],
            'solutions': [
                "Add --exclude=node_modules --exclude=.git to semgrep config",
                "Check internet connection for rule downloads",
                "Increase available memory or scan smaller directories"
            ]
        },
        'gitleaks': {
            'common_issues': [
                "Git repository not initialized",
                "Corrupted git history",
                "Large binary files in git history"
            ],
            'solutions': [
                "Ensure directory is a valid git repository",
                "Try: git fsck --full",
                "Use .gitleaksignore to exclude problematic files"
            ]
        },
        'trivy': {
            'common_issues': [
                "Network issues downloading vulnerability database",
                "No supported dependency files found",
                "Insufficient disk space for cache"
            ],
            'solutions': [
                "Check internet connection and firewall settings", 
                "Ensure package files exist (package.json, requirements.txt, etc.)",
                "Clear trivy cache: trivy clean --all"
            ]
        }
    }
    
    # Add stderr/stdout if helpful
    if stderr and len(stderr.strip()) > 0:
        # Clean up common noise in stderr
        clean_stderr = stderr.strip()
        if len(clean_stderr) > 200:
            clean_stderr = clean_stderr[:200] + "..."
        error_msg += f"\n   Error output: {clean_stderr}"
    
    # Add tool-specific troubleshooting
    tool_lower = tool_name.lower()
    if tool_lower in troubleshooting:
        error_msg += f"\n\n🔧 Common causes for {tool_name}:"
        for issue in troubleshooting[tool_lower]['common_issues']:
            error_msg += f"\n   • {issue}"
        
        error_msg += f"\n\n💡 Try these solutions:"
        for solution in troubleshooting[tool_lower]['solutions']:
            error_msg += f"\n   • {solution}"
    
    # Add general troubleshooting
    error_msg += f"\n\n📋 General troubleshooting:"
    error_msg += f"\n   • Check tool installation: {tool_name} --version"
    error_msg += f"\n   • Verify file permissions in scan directory"
    error_msg += f"\n   • Try running {tool_name} manually on a small test directory"
    
    return error_msg