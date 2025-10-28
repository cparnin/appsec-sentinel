# AppSec-Sentinel MCP Server

Transform Claude Desktop into a conversational security expert with scanning, analysis, and auto-remediation.

## Quick Setup

### 1. Install Scanner Binaries

**Required tools** (must be in system PATH):
- **gitleaks** - Secret detection ([install](https://github.com/gitleaks/gitleaks#installing))
- **trivy** - Dependency scanning ([install](https://trivy.dev/getting-started/installation/))
- **semgrep** - Auto-installed with AppSec-Sentinel Python dependencies

**Quick install (macOS):**
```bash
brew install gitleaks trivy
```

**Quick install (Linux):**
```bash
# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64 -O /usr/local/bin/gitleaks
chmod +x /usr/local/bin/gitleaks

# Trivy
sudo apt-get install trivy  # Debian/Ubuntu
# or
snap install trivy          # Snap
```

### 2. Configure Credentials

```bash
cd /path/to/AppSec-Sentinel/mcp
cp mcp_env.example mcp_env
# Edit mcp_env with AWS and GitHub credentials
```

**Required:**
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` - Bedrock AI access
- `AWS_REGION` - Must match inference profile (e.g., us-east-2)
- `INFERENCE_PROFILE_ID` - Bedrock model ARN
- `GITHUB_TOKEN` - For PR creation ([create token](https://github.com/settings/tokens))

### 3. Update Claude Desktop Config

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "appsec-sentinel": {
      "command": "/path/to/AppSec-Sentinel/.venv/bin/python",
      "args": ["/path/to/AppSec-Sentinel/mcp/appsec_mcp_server.py"],
      "cwd": "/path/to/AppSec-Sentinel",
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        "PYTHONPATH": "/path/to/AppSec-Sentinel/src"
      }
    }
  }
}
```

> 💡 Server reads credentials from `mcp/mcp_env` automatically - no secrets in config file!

### 4. Restart Claude Desktop

Quit completely and reopen. Click 🔨 (hammer) icon to verify 14 AppSec-Sentinel tools appear.

## Usage Examples

```
Scan nodejs-goof for security vulnerabilities

Show cross-file analysis for WebGoat

Auto-fix vulnerabilities in nodejs-goof and create PRs

Generate SBOM for my-project

Assess business impact for vulnerabilities in WebGoat
```

## Available Tools (14 Total)

### Core Tools
| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `scan_repository` | Full security scan | Repo name/path | Vulnerability counts, risk summary |
| `auto_remediate` | AI-powered fixes | Repo name | PR URLs for fixes |
| `get_report` | Detailed report | Repo name | Full vulnerability breakdown |
| `view_report_html` | Open HTML report | Repo name | Opens browser with visual report |
| `health_check` | System diagnostics | None | Scanner availability, config status |

### Analysis Tools
| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `cross_file_analysis` | Attack chain detection | Repo name | Cross-file vulnerabilities, tech stack |
| `assess_business_impact` | Risk assessment | Repo name | Risk level, recommendations |
| `generate_sbom` | Software BOM | Repo name | CycloneDX & SPDX summaries |

### API Tools (for IXaidev/Agents)
| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `get_scan_findings` | All findings paginated | Repo, filters, page | Combined results from all scanners |
| `get_semgrep_findings` | SAST findings only | Repo, severity, page | Pure JSON Semgrep results |
| `get_trivy_findings` | Dependency vulns only | Repo, severity, page | Pure JSON Trivy results |
| `get_gitleaks_findings` | Secrets only | Repo, page | Pure JSON Gitleaks results |
| `get_code_quality_findings` | Linter results only | Repo, linter, page | Pure JSON code quality results |
| `get_sbom_data` | SBOM data | Repo, format | Pure JSON SBOM data |

## Smart Repository Discovery

Use short names like `nodejs-goof` instead of full paths. Searches:
- Current directory
- `~/repos`, `~/projects`, `~/code`
- Custom paths in `REPO_SEARCH_PATHS`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Repository not found" | Use short name (e.g., `nodejs-goof`) or full path |
| "No tools in Claude Desktop" | Check config JSON syntax, verify Python path, restart Claude |
| "Scan failed" | Verify AWS credentials in `mcp/mcp_env` and scanner binaries installed |
| "Scanner not found" | Install gitleaks/trivy and ensure they're in PATH |
| "PR creation failed" | Check `GITHUB_TOKEN` has `repo` permissions, verify git user: `git config --global user.name` |

## How It Works

1. MCP server loads credentials from `mcp/mcp_env` on startup
2. Claude Desktop communicates via stdio (no network exposure)
3. Server executes AppSec-Sentinel commands in target repo
4. Results formatted and returned to Claude
5. Credentials never stored in Claude config

## Security

- Credentials in `mcp/mcp_env` (gitignored, local only)
- AWS Bedrock processes within your infrastructure
- PRs require manual review before merge
- No external communication except AI APIs

---

**Open Source**: MIT Licensed
