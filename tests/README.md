# AppSec-Sentinel Tests

Simple, consolidated test suite for the AppSec-Sentinel security scanner.

## Quick Start

```bash
# Run all tests
pytest tests/test_appsec.py -v

# Run with coverage
pytest tests/test_appsec.py --cov=src --cov-report=html

# Use the test runner
./run_tests.sh
```

## What's Tested

| Module | Tests | Coverage |
|--------|-------|----------|
| Exceptions | ✅ 5 tests | Exception handling |
| Binary Validation | ✅ 4 tests | Security: command injection, null bytes |
| Repo Validation | ✅ 6 tests | Security: path traversal, dangerous chars |
| Language Detection | ✅ 5 tests | Multi-language detection |
| Gitleaks Scanner | ✅ 4 tests | Secrets detection |
| Semgrep Scanner | ✅ 4 tests | SAST analysis |
| Trivy Scanner | ✅ 3 tests | Dependency scanning |
| Threat Modeling | ✅ 8 tests | STRIDE analysis, export, diagrams |

**Total: 43 tests** covering all major functionality

## File Structure

```
tests/
├── test_appsec.py    # All tests (single file)
├── conftest.py        # Shared fixtures
├── pytest.ini         # Test configuration
└── README.md          # This file
```

## Fixtures (in conftest.py)

- `mock_repo` - Fake repository with .git and sample files
- `temp_dir` - Clean temp directory
- `output_dir` - Output directory for scanner results
- `sample_*_output` - Mock scanner outputs (gitleaks, semgrep, trivy)
- `mock_env_vars` - Test environment variables

## Test Markers

Run specific test categories:

```bash
pytest -m security      # Security validation tests only
pytest -m scanner       # Scanner module tests only
pytest -m "not slow"    # Skip slow tests
```

## Coverage Report

After running tests with `--cov`:
```bash
open outputs/coverage/html/index.html
```

## Adding Tests

All tests go in `tests/test_appsec.py`. Use the existing pattern:

```python
class TestYourModule:
    """Test description."""

    def test_your_feature(self, mock_repo):
        """Test what this does."""
        result = your_function(mock_repo)
        assert result is not None
```

That's it!
