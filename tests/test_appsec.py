"""
AppSec-Sentinel Unit Tests

Comprehensive test suite covering:
- Exception handling
- Security validation (path injection, command injection)
- Scanner modules (Gitleaks, Semgrep, Trivy)
- Language detection

Run: pytest tests/test_appsec.py -v
"""

import pytest
import json
import subprocess
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from exceptions import (
    ScannerError, ValidationError, ScanExecutionError, BinaryNotFoundError
)
from scanners.validation import validate_binary_path, validate_repo_path, detect_languages
from scanners.gitleaks import run_gitleaks
from scanners.semgrep import run_semgrep, _categorize_finding
from scanners.trivy import run_trivy_scan as run_trivy


# ============================================================================
# EXCEPTION TESTS
# ============================================================================

class TestExceptions:
    """Test custom exception classes."""

    def test_scanner_error_basic(self):
        """Test basic ScannerError creation."""
        error = ScannerError("Test error")
        assert str(error) == "Test error"
        assert error.scanner is None
        assert error.details == {}

    def test_scanner_error_with_details(self):
        """Test ScannerError with metadata."""
        details = {'path': '/test', 'code': 42}
        error = ScannerError("Error", scanner="semgrep", details=details)
        assert error.scanner == "semgrep"
        assert error.details['path'] == '/test'

    def test_validation_error_inheritance(self):
        """Test ValidationError inherits from ScannerError."""
        error = ValidationError("Invalid")
        assert isinstance(error, ScannerError)
        assert isinstance(error, Exception)

    def test_binary_not_found_error(self):
        """Test BinaryNotFoundError with install hints."""
        details = {'binary': 'semgrep', 'install_hint': 'pip install semgrep'}
        error = BinaryNotFoundError("Not found", scanner="semgrep", details=details)
        assert error.details['install_hint'] == 'pip install semgrep'

    def test_exception_chaining(self):
        """Test exception chaining with 'from' keyword."""
        original = ValueError("Original")
        with pytest.raises(ValidationError) as exc_info:
            try:
                raise original
            except ValueError as e:
                raise ValidationError("Wrapped") from e
        assert exc_info.value.__cause__ is original


# ============================================================================
# VALIDATION & SECURITY TESTS
# ============================================================================

class TestBinaryValidation:
    """Test binary path validation with security checks."""

    def test_default_binary_path(self, mock_env_vars):
        """Test with default binary name."""
        result = validate_binary_path('SEMGREP_BIN', 'semgrep')
        assert result == 'semgrep'

    @pytest.mark.security
    def test_blocks_command_injection(self):
        """Test blocking dangerous characters: ; | & $ ` $(  ${"""
        dangerous = ['tool; rm -rf /', 'tool | cat', 'tool && bad', 'tool$(whoami)', 'tool`cmd`']
        for bad in dangerous:
            with patch.dict(os.environ, {'TEST_BIN': bad}):
                result = validate_binary_path('TEST_BIN', 'default')
                assert result is None, f"Should block: {bad}"

    @pytest.mark.security
    def test_blocks_null_bytes(self, monkeypatch):
        """Test null byte injection prevention."""
        def mock_getenv(key, default=None):
            return 'tool\x00malicious' if key == 'TEST_BIN' else default

        with patch('os.getenv', side_effect=mock_getenv):
            result = validate_binary_path('TEST_BIN', 'default')
            assert result is None

    def test_raises_on_error_flag(self):
        """Test raise_on_error=True raises exception."""
        with patch.dict(os.environ, {'TEST_BIN': 'tool; bad'}):
            with pytest.raises(BinaryNotFoundError):
                validate_binary_path('TEST_BIN', 'default', raise_on_error=True)


class TestRepoValidation:
    """Test repository path validation."""

    def test_valid_repo_path(self, mock_repo):
        """Test successful validation."""
        result = validate_repo_path(str(mock_repo))
        assert result is not None
        assert result.exists()
        assert result.is_dir()

    @pytest.mark.security
    def test_blocks_command_injection(self):
        """Test command injection prevention."""
        dangerous = ['/tmp; rm -rf /', '/tmp | cat', '/tmp && bad', '/tmp$(whoami)']
        for bad in dangerous:
            result = validate_repo_path(bad)
            assert result is None

    @pytest.mark.security
    def test_blocks_null_bytes(self):
        """Test null byte rejection."""
        result = validate_repo_path('/tmp\x00malicious')
        assert result is None

    def test_nonexistent_path(self):
        """Test validation fails for missing paths."""
        result = validate_repo_path('/nonexistent/path/12345')
        assert result is None

    def test_file_not_directory(self, temp_dir):
        """Test fails when path is file not directory."""
        file_path = temp_dir / "test.txt"
        file_path.write_text("not a dir")
        result = validate_repo_path(str(file_path))
        assert result is None

    def test_path_too_long(self):
        """Test extremely long paths are rejected."""
        long_path = '/tmp/' + 'a' * 5000
        result = validate_repo_path(long_path)
        assert result is None


class TestLanguageDetection:
    """Test programming language detection."""

    def test_python_detection(self, temp_dir):
        """Test Python file detection."""
        (temp_dir / "app.py").write_text("print('hello')")
        languages = detect_languages(temp_dir)
        assert 'python' in languages

    def test_javascript_detection(self, temp_dir):
        """Test JS/TS detection."""
        (temp_dir / "app.js").write_text("console.log('hi')")
        (temp_dir / "types.ts").write_text("interface User {}")
        languages = detect_languages(temp_dir)
        assert 'javascript' in languages or 'typescript' in languages

    def test_multiple_languages(self, temp_dir):
        """Test detection of multiple languages."""
        (temp_dir / "app.py").write_text("print('python')")
        (temp_dir / "app.js").write_text("console.log('js')")
        (temp_dir / "Main.java").write_text("public class Main {}")
        languages = detect_languages(temp_dir)
        assert len(languages) >= 2

    def test_ignores_node_modules(self, temp_dir):
        """Test that node_modules is ignored."""
        node_dir = temp_dir / "node_modules" / "pkg"
        node_dir.mkdir(parents=True)
        (node_dir / "index.js").write_text("module.exports = {}")
        (temp_dir / "app.py").write_text("print('hi')")

        languages = detect_languages(temp_dir)
        assert 'python' in languages

    def test_empty_repo(self, temp_dir):
        """Test empty directory."""
        languages = detect_languages(temp_dir)
        assert isinstance(languages, set)
        assert len(languages) == 0


# ============================================================================
# GITLEAKS SCANNER TESTS
# ============================================================================

class TestGitleaks:
    """Test Gitleaks secrets scanner."""

    @patch('scanners.gitleaks.subprocess.run')
    @patch('scanners.gitleaks.validate_binary_path')
    @patch('scanners.gitleaks.validate_repo_path')
    def test_success_with_findings(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir, sample_gitleaks_output
    ):
        """Test successful scan with secrets found."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text(json.dumps(sample_gitleaks_output))
            result = Mock()
            result.returncode = 1  # Gitleaks returns 1 when secrets found
            result.stdout = result.stderr = ""
            return result

        mock_subprocess.side_effect = mock_run
        results = run_gitleaks(str(mock_repo), output_dir)

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('category' in f for f in results)
        assert all(f['category'] == 'security' for f in results)

    @patch('scanners.gitleaks.subprocess.run')
    @patch('scanners.gitleaks.validate_binary_path')
    @patch('scanners.gitleaks.validate_repo_path')
    def test_no_secrets_found(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir
    ):
        """Test scan with no secrets."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text("")
            result = Mock()
            result.returncode = 0
            result.stdout = result.stderr = ""
            return result

        mock_subprocess.side_effect = mock_run
        results = run_gitleaks(str(mock_repo), output_dir)
        assert results == []

    @patch('scanners.gitleaks.validate_binary_path')
    def test_binary_not_found(self, mock_validate_binary, mock_repo):
        """Test when gitleaks binary is missing."""
        mock_validate_binary.return_value = None
        results = run_gitleaks(str(mock_repo))
        assert results == []

    @patch('scanners.gitleaks.subprocess.run')
    @patch('scanners.gitleaks.validate_binary_path')
    @patch('scanners.gitleaks.validate_repo_path')
    def test_timeout_handling(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess, mock_repo
    ):
        """Test timeout error handling."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        mock_subprocess.side_effect = subprocess.TimeoutExpired('gitleaks', 120)

        results = run_gitleaks(str(mock_repo))
        assert results == []


# ============================================================================
# SEMGREP SCANNER TESTS
# ============================================================================

class TestSemgrep:
    """Test Semgrep SAST scanner."""

    @pytest.mark.parametrize("check_id,expected", [
        ('javascript.security.sqli', 'security'),
        ('python.security.injection', 'security'),
        ('javascript.best-practice.unused', 'code_quality'),
        ('python.maintainability.complexity', 'code_quality'),
    ])
    def test_categorize_finding(self, check_id, expected):
        """Test finding categorization."""
        assert _categorize_finding(check_id) == expected

    def test_security_takes_priority(self):
        """Test security patterns prioritized over code quality."""
        result = _categorize_finding('javascript.security.performance.crypto')
        assert result == 'security'

    def test_unknown_defaults_security(self):
        """Test unknown patterns default to security (conservative)."""
        result = _categorize_finding('unknown.rule.pattern')
        assert result == 'security'

    @patch('scanners.semgrep.subprocess.run')
    @patch('scanners.semgrep.validate_repo_path')
    def test_scan_with_findings(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_semgrep_output
    ):
        """Test successful Semgrep scan."""
        mock_validate_repo.return_value = mock_repo

        def create_output_file(*args, **kwargs):
            output_file = output_dir / "semgrep.json"
            output_file.write_text(json.dumps(sample_semgrep_output))
            result = Mock()
            result.returncode = 1
            result.stdout = json.dumps(sample_semgrep_output)
            result.stderr = ""
            return result

        mock_subprocess.side_effect = create_output_file

        results = run_semgrep(str(mock_repo), str(output_dir))
        assert isinstance(results, list)
        assert len(results) > 0

    @patch('scanners.semgrep.subprocess.run')
    @patch('scanners.semgrep.validate_repo_path')
    def test_invalid_repo(self, mock_validate_repo, mock_subprocess):
        """Test with invalid repo path."""
        mock_validate_repo.return_value = None
        results = run_semgrep('/invalid/path')
        assert results == []


# ============================================================================
# TRIVY SCANNER TESTS
# ============================================================================

class TestTrivy:
    """Test Trivy dependency scanner."""

    @patch('scanners.trivy.subprocess.run')
    @patch('scanners.trivy.validate_repo_path')
    def test_scan_with_vulnerabilities(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_trivy_output
    ):
        """Test successful Trivy scan with CVEs."""
        mock_validate_repo.return_value = mock_repo

        def create_output_file(*args, **kwargs):
            output_file = output_dir / "trivy-sca.json"
            output_file.write_text(json.dumps(sample_trivy_output))
            result = Mock()
            result.returncode = 0
            result.stdout = json.dumps(sample_trivy_output)
            result.stderr = ""
            return result

        mock_subprocess.side_effect = create_output_file

        results = run_trivy(str(mock_repo), str(output_dir))
        assert isinstance(results, list)
        assert len(results) > 0

    @patch('scanners.trivy.subprocess.run')
    @patch('scanners.trivy.validate_repo_path')
    def test_no_vulnerabilities(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir
    ):
        """Test scan with clean dependencies."""
        mock_validate_repo.return_value = mock_repo

        result = Mock()
        result.returncode = 0
        result.stdout = json.dumps({"Results": []})
        result.stderr = ""
        mock_subprocess.return_value = result

        results = run_trivy(str(mock_repo), str(output_dir))
        assert results == []

    @patch('scanners.trivy.validate_repo_path')
    def test_invalid_repo(self, mock_validate_repo):
        """Test with invalid repo path."""
        mock_validate_repo.return_value = None
        results = run_trivy('/invalid/path')
        assert results == []
