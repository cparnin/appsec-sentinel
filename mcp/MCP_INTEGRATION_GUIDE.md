# AppSec-Sentinel MCP Integration Guide

---

## What's New

✅ **5 NEW tool-specific MCP endpoints** - Get paginated results per scanner
✅ **Pure JSON responses** - No markdown, ready for your UI
✅ **Grype MCP pattern** - Matches your existing integration style
✅ **Backward compatible** - Old `get_scan_findings` still works

**Code**: `/AppSec-Sentinel/mcp/appsec_mcp_server.py` lines 1436-1768

---

## Tool-Specific Endpoints (NEW - Use These)

Instead of filtering a combined response, call the scanner you need directly:

### 1. `get_semgrep_findings` - SAST Security Issues

```javascript
// Request
{
  "repo_path": "nodejs-goof",
  "page": 1,
  "page_size": 10,
  "severity_filter": "critical"  // optional: critical|high|medium|low
}

// Response
{
  "success": true,
  "tool": "semgrep",
  "repository": "nodejs-goof",
  "page": 1,
  "page_size": 10,
  "total_findings": 45,
  "total_pages": 5,
  "filters_applied": {"severity": "critical"},
  "findings": [
    {
      "id": "semgrep-0",
      "tool": "semgrep",
      "category": "security",
      "severity": "critical",
      "title": "javascript.express.security.audit.xss.mustache",
      "description": "XSS vulnerability detected...",
      "file_path": "app/views/tutorial/a1.dust",
      "line_start": 12,
      "line_end": 12,
      "code_snippet": "{{{ name }}}",
      "cwe": ["CWE-79"],
      "owasp": ["A03:2021"],
      "fix_available": true,
      "remediation": "Use {{name}} instead"
    }
  ],
  "timestamp": "2025-10-15T12:00:00Z"
}
```

---

### 2. `get_trivy_findings` - Dependency Vulnerabilities

```javascript
// Request
{
  "repo_path": "nodejs-goof",
  "page": 1,
  "page_size": 10,
  "severity_filter": "high",  // optional
  "fix_available": true        // optional: filter by fix availability
}

// Response
{
  "success": true,
  "tool": "trivy",
  "repository": "nodejs-goof",
  "page": 1,
  "total_findings": 120,
  "findings": [
    {
      "id": "trivy-0",
      "tool": "trivy",
      "severity": "high",
      "vulnerability_id": "CVE-2021-3807",
      "package_name": "ansi-regex",
      "installed_version": "5.0.0",
      "fixed_version": "5.0.1",
      "title": "CVE-2021-3807: ansi-regex",
      "description": "Regular Expression Denial of Service",
      "file_path": "package-lock.json",
      "cwe": ["CWE-400"],
      "cvss": {"nvd": {"V3Score": 7.5}},
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3807"],
      "fix_available": true,
      "remediation": "Update ansi-regex to version 5.0.1"
    }
  ]
}
```

---

### 3. `get_gitleaks_findings` - Secrets Detection

```javascript
// Request
{
  "repo_path": "nodejs-goof",
  "page": 1,
  "page_size": 10
}

// Response
{
  "success": true,
  "tool": "gitleaks",
  "total_findings": 5,
  "findings": [
    {
      "id": "gitleaks-0",
      "tool": "gitleaks",
      "severity": "critical",
      "rule_id": "aws-access-token",
      "title": "AWS Access Token",
      "file_path": "config/database.js",
      "line_start": 15,
      "commit": "a1b2c3d4",
      "author": "dev@example.com",
      "date": "2024-01-15T10:30:00Z",
      "cwe": ["CWE-798"],
      "remediation": "Remove secret and rotate credentials immediately"
    }
  ]
}
```

---

### 4. `get_code_quality_findings` - Linter Results

```javascript
// Request
{
  "repo_path": "nodejs-goof",
  "page": 1,
  "page_size": 10,
  "linter_filter": "eslint"  // optional: eslint|pylint|checkstyle|golangci-lint|rubocop|clippy|phpstan
}

// Response
{
  "success": true,
  "tool": "code_quality",
  "total_findings": 250,
  "findings": [
    {
      "id": "eslint-0",
      "tool": "eslint",
      "linter": "eslint",
      "language": "javascript/typescript",
      "category": "code_quality",
      "severity": "high",
      "rule_id": "no-unused-vars",
      "title": "no-unused-vars",
      "description": "'userId' is assigned but never used",
      "file_path": "/path/to/routes/profile.js",
      "line_start": 42,
      "column": 15,
      "fix_available": true,
      "remediation": "Auto-fix available"
    }
  ]
}
```

---

### 5. `get_sbom_data` - Software Bill of Materials

```javascript
// Request
{
  "repo_path": "nodejs-goof",
  "format": "both"  // cyclonedx|spdx|both (default: both)
}

// Response
{
  "success": true,
  "repository": "nodejs-goof",
  "format": "both",
  "sbom": {
    "cyclonedx": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "components": [...]
    },
    "spdx": {
      "spdxVersion": "SPDX-2.3",
      "packages": [...]
    }
  }
}
```

---

## Why Tool-Specific Endpoints?

**Before (Old Way)**:
```javascript
// Get ALL findings, then filter
const allFindings = await get_scan_findings({repo_path: "repo"});
const semgrepOnly = allFindings.findings.filter(f => f.tool === "semgrep");
```

**After (New Way)**:
```javascript
// Get ONLY Semgrep findings directly
const semgrepFindings = await get_semgrep_findings({repo_path: "repo"});
```

**Benefits**:
- ✅ Cleaner separation for your UI tabs/views
- ✅ Less data transfer (only what you need)
- ✅ Tool-specific filters (e.g., `fix_available` for Trivy)
- ✅ Matches your Grype integration pattern

---

## Old Combined Endpoint (Still Works)

The original `get_scan_findings` tool still exists and works:

```javascript
// OLD - Still available for backward compatibility
{
  "repo_path": "nodejs-goof",
  "page": 1,
  "page_size": 10,
  "tool_filter": "semgrep",      // Filter AFTER loading all data
  "severity_filter": "critical",
  "category_filter": "security"
}
```

But the new tool-specific endpoints are **recommended** for cleaner architecture.

---

## Integration Checklist

- [ ] Call `scan_repository` first to generate data
- [ ] Use new tool-specific endpoints for each scanner type
- [ ] Parse JSON from `response.content[0].text`
- [ ] Implement pagination (page 1, 2, 3...)
- [ ] Handle empty results gracefully (`total_findings: 0`)
- [ ] Display in separate UI sections per tool

---

## File Locations

**AppSec-Sentinel MCP Server**: `/AppSec-Sentinel/mcp/appsec_mcp_server.py`
- Lines 124-191: Tool definitions
- Lines 1436-1768: New tool implementations

**Scan Output Files**:
- Semgrep: `outputs/raw/semgrep.json`
- Gitleaks: `outputs/raw/gitleaks.json`
- Trivy: `outputs/raw/trivy-sca.json`
- ESLint: `outputs/raw/eslint.json`
- Pylint: `outputs/raw/pylint.json`
- SBOM: `outputs/sbom/sbom.cyclonedx.json` and `sbom.spdx.json`


