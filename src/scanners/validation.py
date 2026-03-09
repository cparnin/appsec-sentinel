"""
Shared validation utilities for security scanner modules.

This module provides common validation functions used across all scanner modules
to prevent code duplication and ensure consistent security practices.
"""

import os
from pathlib import Path
from exceptions import ValidationError, BinaryNotFoundError
from logging_config import get_logger

logger = get_logger(__name__)

def validate_binary_path(env_var: str, default_bin: str, raise_on_error: bool = False) -> str:
    """
    Securely validate binary path from environment variable.
    
    Args:
        env_var: Environment variable name
        default_bin: Default binary name
        raise_on_error: If True, raise exceptions instead of returning None
        
    Returns:
        str: Validated binary path or None if invalid (when raise_on_error=False)
        
    Raises:
        BinaryNotFoundError: When binary validation fails (when raise_on_error=True)
    """
    try:
        bin_path = os.getenv(env_var, default_bin)
        
        # Basic validation
        if not bin_path or not isinstance(bin_path, str):
            error_msg = f"Invalid binary path from {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None
            
        # Check for dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '$(', '${', '\n', '\r']
        if any(char in bin_path for char in dangerous_chars):
            error_msg = f"Potentially dangerous characters in binary path: {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None
            
        # Remove null bytes
        clean_path = bin_path.replace('\x00', '')
        if clean_path != bin_path:
            error_msg = f"Invalid characters in binary path: {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None
            
        return clean_path
        
    except BinaryNotFoundError:
        raise  # Re-raise our custom exception
    except Exception as e:
        error_msg = f"Error validating binary path {env_var}: {e}"
        logger.error(error_msg)
        if raise_on_error:
            raise BinaryNotFoundError(error_msg, scanner=default_bin)
        return None

def validate_repo_path(repo_path: str, raise_on_error: bool = False) -> Path | None:
    """
    Securely validate repository path to prevent command injection and path traversal.

    This is the single source of truth for repo path validation across the project.
    Includes system directory blocking, permission checks, and git repo detection.

    Args:
        repo_path: User-provided repository path
        raise_on_error: If True, raise exceptions instead of returning None

    Returns:
        Path: Validated Path object or None if invalid (when raise_on_error=False)

    Raises:
        ValidationError: When path validation fails (when raise_on_error=True)
    """
    def _fail(error_msg: str, details: dict | None = None):
        logger.error(error_msg)
        if raise_on_error:
            raise ValidationError(error_msg, details=details or {'path': repo_path})
        return None

    try:
        # Input sanitization
        if not repo_path or not isinstance(repo_path, str):
            return _fail("Repository path must be a non-empty string")

        # Check path length early
        if len(repo_path) > 4096:
            return _fail("Repository path too long (max 4096 characters)")

        # Remove null bytes
        clean_path = repo_path.replace('\x00', '')
        if clean_path != repo_path:
            return _fail("Invalid characters in repository path")

        # Check for command injection patterns
        dangerous_patterns = [';', '|', '&', '$', '`', '$(', '${']
        if any(pattern in clean_path for pattern in dangerous_patterns):
            return _fail("Potentially dangerous characters in repository path")

        # Convert to Path and resolve
        try:
            path = Path(clean_path).resolve()
        except (OSError, ValueError) as e:
            return _fail(f"Invalid repository path format: {e}")

        # Path traversal protection
        if '..' in clean_path:
            original_parts = Path(clean_path).parts
            resolved_parts = path.parts
            if len(resolved_parts) < len(original_parts) - clean_path.count('..'):
                return _fail("Path traversal attempt detected")

        # Existence and type checks
        if not path.exists():
            return _fail(f"Repository path does not exist: {path}")
        if not path.is_dir():
            return _fail(f"Repository path is not a directory: {path}")

        # Permission check
        if not os.access(path, os.R_OK):
            return _fail(f"Repository path is not readable: {path}")

        # Block system directories
        system_dirs = {
            Path('/etc'), Path('/sys'), Path('/proc'), Path('/dev'),
            Path('/boot'), Path('/root'), Path('/var/log'),
            Path('C:/Windows'), Path('C:/System32'), Path('C:/Program Files')
        }
        for sys_dir in system_dirs:
            try:
                if sys_dir.exists() and (path == sys_dir or sys_dir in path.parents or path in sys_dir.parents):
                    return _fail(f"Cannot scan system directory: {path}")
            except OSError:
                continue

        # Warn about large directories
        try:
            item_count = sum(1 for _ in path.iterdir() if _.is_file() or _.is_dir())
            if item_count > 10000:
                logger.warning(f"Large directory detected ({item_count} items). Scan may take a long time.")
        except (OSError, PermissionError):
            pass

        # Warn if not a git repository
        if not (path / '.git').exists():
            logger.warning(f"Directory is not a git repository: {path}")
            logger.warning("Some scanners (like gitleaks) require git history to function properly")

        return path

    except ValidationError:
        raise
    except Exception as e:
        error_msg = f"Error validating repository path: {e}"
        logger.error(error_msg)
        if raise_on_error:
            raise ValidationError(error_msg, details={'path': repo_path, 'original_error': str(e)})
        return None

def detect_languages(repo_path: Path) -> dict:
    """
    Detect programming languages in a repository by scanning file extensions.
    Returns a dictionary of language counts to help determine dominant languages.

    Args:
        repo_path: Path to repository to analyze

    Returns:
        dict: Dictionary mapping language names to file counts (e.g., {'javascript': 150, 'python': 3})
    """
    # Comprehensive language mapping based on file extensions
    language_map = {
        # JavaScript/TypeScript ecosystem
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',

        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyi': 'python',

        # Java/JVM
        '.java': 'java',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.groovy': 'groovy',
        '.scala': 'scala',

        # C/C++/C#
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.cs': 'csharp',

        # Go
        '.go': 'go',

        # Rust
        '.rs': 'rust',

        # Ruby
        '.rb': 'ruby',
        '.erb': 'ruby',

        # PHP
        '.php': 'php',
        '.phtml': 'php',

        # Swift
        '.swift': 'swift',

        # Other languages
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',
        '.r': 'r',
        '.R': 'r',
    }

    language_counts = {}
    files_checked = 0
    max_files_to_check = 20000  # Increased limit for better accuracy

    try:
        # Scan repository for file extensions
        for file_path in repo_path.rglob('*'):
            # Stop if we've checked too many files
            if files_checked >= max_files_to_check:
                logger.warning(f"Reached max file check limit ({max_files_to_check}), stopping language detection")
                break

            # Skip directories
            if file_path.is_dir():
                continue

            # Skip common ignored directories
            path_parts = file_path.parts
            ignored_dirs = {
                'node_modules', '.git', '__pycache__', '.venv', 'venv',
                'dist', 'build', '.cache', 'target', 'vendor', '.idea',
                '.vscode', 'coverage', '.pytest_cache', 'outputs'
            }
            if any(ignored in path_parts for ignored in ignored_dirs):
                continue

            files_checked += 1

            # Check file extension
            file_extension = file_path.suffix.lower()
            if file_extension in language_map:
                language = language_map[file_extension]
                language_counts[language] = language_counts.get(language, 0) + 1

        detected_list = sorted(language_counts.keys())
        logger.info(f"🔍 Language detection: Found {len(detected_list)} languages in {files_checked} files")
        logger.debug(f"Title breakdown: {language_counts}")

        return language_counts

    except Exception as e:
        logger.warning(f"Language detection failed: {e}")
        return {}