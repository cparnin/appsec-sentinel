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
# Edit mcp_env with LLM provider and GitHub credentials
```

**Required for scanning:** None - scanning works without any API keys

**Required for auto-remediation (choose one LLM provider):**
- **OpenAI**: `OPENAI_API_KEY`, `AI_PROVIDER=openai`, `AI_MODEL=gpt-4o-mini`
- **Claude**: `CLAUDE_API_KEY`, `AI_PROVIDER=claude`, `AI_MODEL=claude-sonnet-4-20250514`
- **AWS Bedrock**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `INFERENCE_PROFILE_ID`, `AI_PROVIDER=aws_bedrock`

**Required for PR creation:**
- `GITHUB_TOKEN` - For creating fix PRs ([create token](https://github.com/settings/tokens))

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

Quit completely and reopen. Click 🔨 (hammer) icon to verify 15 AppSec-Sentinel tools appear.

## Usage Examples

```
Scan nodejs-goof for security vulnerabilities

Show cross-file analysis for WebGoat

Auto-fix vulnerabilities in nodejs-goof and create PRs

Generate threat model for my-application

Generate SBOM for my-project

Assess business impact for vulnerabilities in WebGoat
```

## Available Tools (15 Total)

### Core Tools
| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `scan_repository` | Full security scan | Repo name/path | Vulnerability counts, risk summary |
| `auto_remediate` | LLM-powered fixes | Repo name | PR URLs for fixes |
| `get_report` | Detailed report | Repo name | Full vulnerability breakdown |
| `view_report_html` | Open HTML report | Repo name | Opens browser with visual report |
| `health_check` | System diagnostics | None | Scanner availability, config status |

### Analysis Tools
| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `cross_file_analysis` | Attack chain detection | Repo name | Cross-file vulnerabilities, tech stack |
| `assess_business_impact` | Risk assessment | Repo name | Risk level, recommendations |
| `generate_sbom` | Software BOM | Repo name | CycloneDX & SPDX summaries |
| `generate_threat_model` | STRIDE threat analysis | Repo name | Architecture, threats, risk level |

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
| "Scan failed" | Verify scanner binaries installed (gitleaks, trivy). API keys not needed for scanning. |
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
- Scanning runs 100% locally (no API calls)
- Auto-remediation uses LLM APIs (OpenAI/Claude/Bedrock)
- PRs require manual review before merge

---

**Open Source**: MIT Licensed
