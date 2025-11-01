# AppSec-Sentinel Architecture

## Output Structure: Multi-Repo/Branch Design

### Directory Layout
```
outputs/
  └── {repo_name}/
      └── {branch}/
          ├── raw/                    # Scanner JSON outputs
          │   ├── semgrep.json       # SAST findings
          │   ├── gitleaks.json      # Secret detection
          │   ├── trivy-sca.json     # Dependency vulnerabilities
          │   └── eslint.json        # Code quality (JS/TS)
          ├── sbom/                   # SBOM compliance files
          │   ├── sbom.cyclonedx.json
          │   └── sbom.spdx.json
          ├── report.html             # Interactive HTML report
          ├── pr-findings.txt         # PR summary for auto-remediation
          ├── threat_model.json       # Structured threat data (STRIDE)
          ├── THREAT_MODEL.md         # Human-readable threat report
          └── architecture.mermaid    # Visual architecture diagram
```

### Smart Path Resolution (`src/path_utils.py`)

**Git Context Detection:**
```python
get_git_context(repo_path) → {'repo': 'org_reponame', 'branch': 'main'}
```

**Automatic Discovery:**
1. Extracts repo name from `git remote origin url`
2. Gets current branch from `git rev-parse --abbrev-ref HEAD`
3. Sanitizes special characters (e.g., `feature/auth` → `feature_auth`)
4. Falls back to directory name + "main" for non-git repos

**Path Generation:**
```python
get_output_path(repo_path, base_output_dir="outputs")
# Returns: outputs/{repo_name}/{branch}/
```

**Cleanup Strategy:**
```python
cleanup_old_scans(output_path)
# Removes all existing content in branch directory
# Keeps only the most recent scan per branch
```

## Integration Points

### CLI Mode (`src/main.py`)
```python
output_path = get_output_path(repo_path, BASE_OUTPUT_DIR)
cleanup_old_scans(output_path)
output_dirs = setup_output_directories(output_path)
output_dir = output_dirs['base']  # Use this for all operations
```

### Web Mode (`src/web_app.py`)
```python
# Same path resolution as CLI
output_path = get_output_path(str(validated_path), BASE_OUTPUT_DIR)
LAST_SCAN_OUTPUT_DIR = output_dir  # Track for report serving
```

### CI/CD Mode (GitHub Actions)
- Uses `run_auto_mode()` which automatically applies repo/branch structure
- Works with `GITHUB_WORKSPACE` environment variable
- No configuration changes needed in `action.yml`

### MCP Server (`mcp/appsec_mcp_server.py`)
```python
def _get_repo_output_path(self, repo_path):
    """Get the output path for a specific repository using new structure"""
    if self.get_output_path:
        output_path = self.get_output_path(repo_path, self.base_output_dir)
        return str(output_path)
    else:
        # Fallback to old flat structure for backward compatibility
        return os.path.join(self.ix_guard_path, "outputs")
```

## Key Benefits

**Multi-Repository Support:**
- Scan multiple repos concurrently without conflicts
- Each repo has isolated output namespace

**Branch-Aware Security Tracking:**
- Compare security posture: `main` vs `feature-branch` vs `release`
- Historical tracking: "Has this branch improved?"
- Natural CI/CD mapping: Works with `${{ github.repository }}` and `${{ github.ref_name }}`

**Automatic Cleanup:**
- Only keeps most recent scan per branch
- Prevents disk space accumulation
- No manual maintenance required

**Zero Breaking Changes:**
- All existing functionality preserved
- Backward compatible fallback for older versions
- Same API surface for all consumers

## Implementation Details

### Path Sanitization
```python
sanitize_path_component("feature/auth-fix")  # → "feature_auth-fix"
sanitize_path_component("my-org/my-repo")    # → "my-org_my-repo"
```

**Handles:**
- Forward/backward slashes (path separators)
- Special filesystem characters (`<>:"|?*`)
- Leading/trailing dots and spaces
- Empty strings (fallback to "unknown")

### Git Context Extraction

**Repository Name:**
```bash
# From remote URL: git@github.com:user/repo.git
→ "user_repo"

# From remote URL: https://github.com/org/project.git
→ "org_project"

# No remote configured → directory name
→ "repo-directory-name"
```

**Branch Name:**
```bash
git rev-parse --abbrev-ref HEAD  # → "main", "feature/new-auth", etc.
```

**Timeout Protection:** 5-second timeout on all git commands to prevent hangs

### Directory Setup Flow

```python
# 1. Determine output path based on git context
output_path = get_output_path(repo_path)
# → outputs/cparnin_nodejs-goof/main/

# 2. Clean up old scans (keeps only most recent)
cleanup_old_scans(output_path)

# 3. Create directory structure
output_dirs = setup_output_directories(output_path)
# Creates: base/, raw/, sbom/

# 4. Use throughout scan
all_findings = run_security_scans(repo_path, scanners, output_dirs['base'])
generate_html_report(findings, summary, str(output_dirs['base']), repo_path)
```

## Deployment Modes Matrix

| Mode | Path Resolution | Cleanup | Notes |
|------|----------------|---------|-------|
| **CLI** | ✅ Git-aware | ✅ Auto | Interactive repo selection |
| **Web** | ✅ Git-aware | ✅ Auto | Tracks last scan for serving |
| **CI/CD** | ✅ Git-aware | ✅ Auto | Uses `GITHUB_WORKSPACE` |
| **MCP** | ✅ Git-aware | ✅ Auto | Fallback for compatibility |

## Performance Characteristics

**Git Operations:** O(1) - Single remote lookup, single branch check
**Cleanup:** O(n) - Linear in number of files per branch (typically < 100)
**Path Resolution:** O(1) - String operations only

**Typical Overhead:** < 50ms per scan initialization

## Error Handling

**Git Failures:**
- Timeout → Use directory name + "main"
- No .git directory → Use directory name + "main"
- No remote configured → Use directory name + current branch

**Filesystem Errors:**
- Permission denied → Propagate to caller
- Disk full → Propagate to caller
- Path too long (>4096) → Validation error

**Result:** Graceful degradation - always produces valid output path

## Adding New Scanners/Linters

### Future-Proof Scanner Pattern

**✅ All current and future scanners automatically work with repo/branch structure!**

**Standard Scanner Signature:**
```python
def run_scanner(repo_path: str, output_dir: str = None) -> list:
    """
    Args:
        repo_path: Path to repository
        output_dir: Output directory (repo/branch-aware path provided by AppSec-Sentinel)

    Returns:
        list: Standardized findings
    """
    # 1. Handle output_dir parameter
    if output_dir is None:
        output_path = Path("../outputs/raw").resolve()
    else:
        output_path = Path(output_dir).resolve()

    # 2. Ensure directory exists
    output_path.mkdir(parents=True, exist_ok=True)

    # 3. Write to output_dir / "scanner_name.json"
    output_file = output_path / "scanner_name.json"

    # 4. Run scanner, parse results, return findings
    # ...
```

### Why This Works

**Automatic Compatibility:**
- AppSec-Sentinel passes correct `output_dir` for repo/branch
- Scanner writes to that directory
- All modes (CLI/Web/CI/CD/MCP) get correct path automatically

**Example Flow:**
```python
# AppSec-Sentinel determines path
output_path = get_output_path(repo_path)  # → outputs/nodejs-goof/main/

# Scanner receives this path
run_eslint(repo_path, str(output_path / "raw"))

# Scanner writes to: outputs/nodejs-goof/main/raw/eslint.json
```

### Adding a New Scanner

**Reference Implementation:** See `src/scanners/eslint.py` or `src/scanners/pylint.py`

**Steps:**
1. Copy existing scanner (e.g., `eslint.py`)
2. Implement scanner-specific logic
3. Add import to `src/main.py`
4. Add to scanner pipeline with language detection
5. Update MCP parser (1 JSON parse block)

**That's it!** - Output path handling is automatic

### Current Scanners (All Compatible)

| Scanner | Type | Output File | Status |
|---------|------|-------------|--------|
| Semgrep | SAST | semgrep.json | ✅ Compatible |
| Gitleaks | Secrets | gitleaks.json | ✅ Compatible |
| Trivy | Dependencies | trivy-sca.json | ✅ Compatible |
| ESLint | Code Quality | eslint.json | ✅ Compatible |
| Pylint | Code Quality | pylint.json | ✅ Compatible |
| Checkstyle | Code Quality | checkstyle.json | ✅ Compatible |
| golangci-lint | Code Quality | golangci-lint.json | ✅ Compatible |
| RuboCop | Code Quality | rubocop.json | ✅ Compatible |
| Clippy | Code Quality | clippy.json | ✅ Compatible |
| PHPStan | Code Quality | phpstan.json | ✅ Compatible |

**Future Scanners:** Automatically compatible if they follow the template pattern

## Threat Modeling Architecture

### Overview

Automated threat modeling generates STRIDE analysis, architecture diagrams, and attack surface assessments. Integrates with security scan findings to provide architectural context.

### Components

**Core Module:** `src/threat_modeling/threat_analyzer.py`

**Capabilities:**
- Framework detection (Express, Flask, Spring, Django, Rails, Laravel, FastAPI)
- Entry point discovery (HTTP routes, API endpoints, input handlers)
- Data store identification (databases, ORMs)
- Trust boundary mapping
- STRIDE threat categorization
- Mermaid diagram generation

### Output Files

```
outputs/{repo}/{branch}/
  ├── threat_model.json       # Structured JSON with STRIDE analysis
  ├── THREAT_MODEL.md         # Human-readable markdown report
  └── architecture.mermaid    # Visual architecture diagram
```

### Integration Points

**CLI:** `src/main.py` - Menu option for threat model generation
**Web:** `src/web_app.py` - `/threat-model` POST endpoint
**MCP:** `mcp/appsec_mcp_server.py` - `generate_threat_model` tool

### Processing Flow

```
Repository Analysis
    ↓
Framework/Component Detection
    ↓
Entry Point & Data Store Discovery
    ↓
Trust Boundary Identification
    ↓
STRIDE Mapping (with security findings)
    ↓
Threat Scenario Generation
    ↓
Export (JSON + Markdown + Mermaid)
```

### STRIDE Categories

- **Spoofing** - Authentication bypass, identity theft
- **Tampering** - SQL injection, XSS, CSRF, data integrity
- **Repudiation** - Audit logging, non-repudiation
- **Information Disclosure** - Secrets, sensitive data exposure
- **Denial of Service** - Resource exhaustion, availability
- **Elevation of Privilege** - Authorization bypass, RCE

See [THREAT_MODELING.md](THREAT_MODELING.md) for full documentation.

## Future Enhancements

**Potential Additions:**
- Scan history: Keep last N scans per branch (configurable retention)
- Cross-branch diff: Compare security findings across branches
- Trend analysis: Track vulnerability counts over time
- API endpoint: List available scans by repo/branch
- Threat model versioning: Track architecture changes over time
- Custom threat frameworks: Support PASTA, VAST, OCTAVE

**Extension Points:**
```python
# src/path_utils.py
def list_available_scans(base_output_dir: str = "outputs") -> Dict[str, Dict[str, Path]]
# Already implemented - returns all scans organized by repo/branch
```

## Testing Strategy

**Unit Tests:** (TODO)
- Path sanitization edge cases
- Git context extraction with various URL formats
- Fallback behavior for non-git repos

**Integration Tests:** (TODO)
- Full scan with repo/branch structure
- Concurrent scans of different repos
- Branch switching during scans

**Verification:**
```bash
# Manual verification
python3 -c "
import sys; sys.path.insert(0, 'src')
from path_utils import get_output_path
print(get_output_path('/path/to/repo', 'outputs'))
"
# Expected: outputs/{repo_name}/{branch}/
```

## Backward Compatibility

**MCP Server:**
```python
# Tries new path structure first
if self.get_output_path:
    return self.get_output_path(repo_path, self.base_output_dir)
else:
    # Fallback to old structure
    return os.path.join(self.ix_guard_path, "outputs")
```

**Legacy Output Structure:** `outputs/` (flat) → Still accessible via fallback

**Migration Path:** None required - automatically adopts new structure on next scan

---

**Version:** 1.4.0
**Last Updated:** 2025-01-XX
**Status:** Production Ready
