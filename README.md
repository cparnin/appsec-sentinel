# AppSec-Sentinel

All-In-One Appsec Tool: SAST, SCA, Secrets, SBOM, Code Quality, AI Code Fixes, Claude Desktop MCP Integration (with POC exploit capability), Attack Chain Analysis, CLI/Web/CICD Modes, Reporting
> 📖 **Open Source** - Licensed under the MIT License. Free for personal and commercial use.

## Features

- **Multi-Scanner Engine** - Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies) + code quality linters
- **Code Quality Scanning** - ESLint, Pylint, Checkstyle, golangci-lint, RuboCop with bundled configs (no project setup needed)
- **Auto-Remediation** - Creates GitHub PRs with LLM-generated code fixes using OpenAI/Claude/Bedrock (optional)
- **Cross-File Analysis** - Traces attack chains across multiple files and languages
- **Flexible AI Providers** - OpenAI (default), Claude, or AWS Bedrock
- **10+ Languages** - JavaScript, TypeScript, Python, Java, Go, Ruby, Rust, C#, PHP, Swift, Kotlin
- **3 Deployment Modes** - Web UI, CLI, and GitHub Actions CI/CD
- **MCP Server** - Model Context Protocol integration for Claude Desktop
- **Compliance** - Automatic SBOM generation (CycloneDX & SPDX)

## Quick Start

For a super fast setup guide, see [QUICKSTART.md](QUICKSTART.md).

### What You Get Out-of-the-Box

**Security scanning**:
- Semgrep (SAST) - included via pip
- Gitleaks (secrets) - requires installation (see QUICKSTART)
- Trivy (dependencies) - requires installation (see QUICKSTART)

**Code quality scanning is optional** - install what you need:
- ESLint (JavaScript/TypeScript) - `npm install -g eslint`
- Pylint (Python) - auto-installs if missing
- Checkstyle, golangci-lint, RuboCop, Clippy, PHPStan - install as needed

> 💡 **Skip code quality?** Just ignore the "⚠️ not installed" warnings - security scanning still works perfectly!

### Prerequisites

Configure LLM provider in `.env` (only needed for auto-remediation feature):
- **OpenAI**: `OPENAI_API_KEY`, `AI_PROVIDER=openai`, `AI_MODEL=gpt-4o-mini`
- **Claude**: `CLAUDE_API_KEY`, `AI_PROVIDER=claude`, `AI_MODEL=claude-sonnet-4-20250514`
- **Gemini**: `GEMINI_API_KEY`, `AI_PROVIDER=gemini`, `AI_MODEL=gemini-1.5-flash`
- **AWS Bedrock**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `INFERENCE_PROFILE_ID`, `AI_PROVIDER=aws_bedrock` (see env.example for all options)

### Web Interface

```bash
./start_web.sh
# → Opens http://localhost:8000
```

**Features:**
- Tool selection via checkboxes (Semgrep, Trivy, Gitleaks, Code Quality, SBOM)
- Visual reports with executive summaries
- Download SBOM files (CycloneDX & SPDX)

<img width="1088" height="674" alt="Screenshot 2025-11-05 at 10 06 36 AM" src="https://github.com/user-attachments/assets/60c9c173-4df9-4573-b7db-bbb8745d8968" />

### CLI Mode

```bash
./start_cli.sh
# → Interactive menu with tool selection, severity levels, and auto-fix options
```

**Features:**
- Choose which tools to run (SAST, secrets, dependencies, code quality, SBOM)
- Select scan level (critical-high or all)
- Configure auto-remediation mode

<img width="821" height="264" alt="Screenshot 2025-11-05 at 10 08 44 AM" src="https://github.com/user-attachments/assets/24533bc6-fe76-4064-a00f-9be0411345e4" />

### CI/CD Integration
```bash
# Copy workflow template
cp projects/security-scan.yml .github/workflows/

# Add GitHub secret:
#   - OPENAI_API_KEY (or CLAUDE_API_KEY, or AWS credentials)

git add .github/workflows/security-scan.yml
git commit -m "Add AppSec-Sentinel security scanning"
git push
```

## How It Works

1. **Scan** - Runs 3 scanners in parallel (SAST, secrets, dependencies)
2. **Analyze** - Cross-file AST analysis identifies attack chains across files using graph traversal
3. **Remediate** - LLM generates fixes and creates separate PRs for code vs dependencies (requires API keys)
4. **Report** - HTML reports + SBOM files (CycloneDX & SPDX)

<img width="252" height="119" alt="Screenshot 2025-11-05 at 10 16 50 AM" src="https://github.com/user-attachments/assets/0ca6a638-b6a1-49dc-8402-52b8642c1650" />

### MCP Integration

Turn Claude Desktop into a conversational security expert - scan, analyze, and auto-remediate through natural language.

**Setup:** Add to Claude Desktop config:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "appsec-sentinel": {
      "command": "/path/to/appsec-sentinel/.venv/bin/python",
      "args": ["/path/to/appsec-sentinel/mcp/appsec_mcp_server.py"],
      "cwd": "/path/to/appsec-sentinel",
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        "PYTHONPATH": "/path/to/appsec-sentinel/src"
      }
    }
  }
}
```

> 💡 Credentials in `mcp/mcp_env`

**14 MCP Tools Available:**
- **Core:** `scan_repository` • `auto_remediate` • `get_report` • `view_report_html` • `health_check`
- **Analysis:** `cross_file_analysis` • `assess_business_impact` • `generate_sbom`
- **API Tools:** `get_scan_findings` • `get_semgrep_findings` • `get_trivy_findings` • `get_gitleaks_findings` • `get_code_quality_findings` • `get_sbom_data`

**Usage:** "Scan <insert repo name> for vulnerabilities" → detailed findings with file paths, line numbers, remediation

[Full MCP setup guide →](mcp/README.md)

<img width="748" height="356" alt="Screenshot 2025-11-05 at 10 13 04 AM" src="https://github.com/user-attachments/assets/5521fc39-08a1-4a6b-a674-f63df50668ad" />

## Auto-Fix Modes
- **Mode 1**: SAST + secrets (1 PR)
- **Mode 2**: Dependencies only (1 PR)
- **Mode 3**: Both (2 separate PRs) - Recommended
- **Mode 4**: Scan only (no PRs)

<img width="827" height="162" alt="Screenshot 2025-11-05 at 10 12 13 AM" src="https://github.com/user-attachments/assets/f8754320-5342-46fc-8492-8c8789417bc0" />

## Cross-File Analysis

Traces attack paths across multiple files and languages:

- **Multi-Language AST** - Real code understanding (not regex)
- **Data Flow Tracing** - Entry points → attack paths → sensitive sinks
- **Framework-Aware** - Express, Spring, Django, Rails, Laravel, ASP.NET

<img width="1064" height="234" alt="Screenshot 2025-11-05 at 10 19 58 AM" src="https://github.com/user-attachments/assets/3bec2886-8000-49ad-a805-b9e27d3cbfb0" />


See [Architecture Diagram →](ARCHITECTURE.md)

## Code Quality Scanning

AppSec-Sentinel includes code quality scanning that works on any repository without configuration.

**Supported Languages:**
- ✅ **JavaScript/TypeScript** - ESLint (auto-detects v8 vs v9, uses bundled config)
- ✅ **Python** - Pylint (auto-installs to virtualenv)
- ✅ **Java** - Checkstyle (fully integrated in all modes)
- ✅ **Go** - golangci-lint (fully integrated in all modes)
- ✅ **Ruby** - RuboCop (fully integrated in all modes)
- ✅ **Rust** - Clippy (official Rust linter, 600+ checks)
- ✅ **PHP** - PHPStan (static analysis without running code)
- 🔜 **C#** - Coming soon (Roslyn Analyzers)
- 🔜 **Swift** - Coming soon (SwiftLint for iOS/macOS)
- 🔜 **Kotlin** - Coming soon (ktlint/detekt for Android/JVM)

**How It Works:**
1. Auto-detects languages by scanning file extensions
2. Checks for repo config (.eslintrc.json, etc.)
3. Falls back to bundled config if repo has none
4. Runs in parallel with security scanners (no performance penalty)

**Example:**
```bash
📊 Detected languages: javascript, python
🔍 Starting scan (3 security + 2 code quality scanners)...
📋 No ESLint config in repo - using default config
✅ ESLint (Code Quality): 106 code quality issues
✅ Pylint (Code Quality): 23 code quality issues
🎯 Scan complete: 119 security issues + 129 code quality issues
```

<img width="1117" height="350" alt="Screenshot 2025-11-05 at 10 21 13 AM" src="https://github.com/user-attachments/assets/30ebc957-59d0-4332-84eb-6d8f1388d34a" />

---

## Optional: Install Code Quality Linters

**Want code quality scanning?** Install the linters for your languages:

```bash
# JavaScript/TypeScript
npm install -g eslint

# Python (auto-installs if missing)
pip install pylint

# Java
brew install checkstyle  # macOS
# or download from https://checkstyle.org/

# Go
brew install golangci-lint  # macOS
# or: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh

# Ruby
gem install rubocop

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh  # Includes clippy

# PHP
composer global require phpstan/phpstan
```
---

## Configuration

Edit `.env` file:
```bash
# Tool Selection (CLI/Web only - CI/CD always runs all)
APPSEC_TOOLS=all                    # 'all' or comma-separated: semgrep,trivy,gitleaks,code_quality,sbom
                                    # Examples:
                                    #   all - Run all tools (default)
                                    #   semgrep,gitleaks - Only SAST + secrets
                                    #   trivy - Only dependency scanning

# Code quality scanning (enabled by default, gracefully skips if linters not installed)
APPSEC_CODE_QUALITY=true

# Scan level (only affects security findings)
APPSEC_SCAN_LEVEL=critical-high  # or 'all'

# AI determinism
APPSEC_AI_TEMPERATURE=0.0

# Auto-fix settings
APPSEC_AUTO_FIX=true
APPSEC_AUTO_FIX_MODE=3  # 1=SAST, 2=deps, 3=both, 4=scan only
```

**Bundled Configs**:
- `configs/eslint.config.js` / `eslintrc.v8.json` - JavaScript/TypeScript
- `configs/checkstyle.xml` - Java
- `configs/golangci.yml` - Go
- `configs/rubocop.yml` - Ruby
- `configs/clippy.toml` - Rust
- `configs/phpstan.neon` - PHP
- `configs/.gitleaks.toml` - Secrets

## Documentation

- **[MCP Setup](mcp/README.md)** - Model Context Protocol integration
- **[Architecture](ARCHITECTURE.md)** - System architecture and design patterns

## FAQ

**Q: Is LLM-generated code safe to merge?**

A: All fixes require manual review via PR. We use deterministic LLM settings (temperature=0.0) and only fix proven patterns (SQL injection, XSS, hardcoded secrets). Your existing tests validate changes. Separate PRs for code vs dependencies minimize risk. ~80% of fixes are production-ready after quick review.

**Q: What data gets sent to LLM providers?**

A: Only vulnerability metadata (file path, line number, vulnerability type, code snippet). **Never** your full codebase. Secrets are flagged locally and **never** sent to LLMs. You control which findings trigger LLM analysis. Note: Scanning and cross-file analysis run **100% locally** with zero API calls.

**Q: Which mode should I use?**

- **GitHub Actions** - Automated security in CI/CD (scans every PR)
- **Web UI** - Visual reports for teams and management
- **CLI** - Deep-dive analysis for security consultants
- **MCP** - Conversational security with Claude Desktop

All modes use the same scanning engine. Choose based on your workflow.

**Q: Do I need to install linters for code quality?**

A: No - security scanning works without any linters. Code quality is **optional** and gracefully skips if tools aren't installed. Install linters (ESLint, Pylint, etc.) only if you want code smell detection. Set `APPSEC_CODE_QUALITY=false` to disable entirely.

**Q: How is this different from other security scanners?**

A: **Cross-file attack chain detection** - we trace vulnerabilities across multiple files and languages using AST analysis and graph traversal, not just single-file pattern matching. Plus optional LLM-generated fixes and zero-config SBOM generation.


**Q: Are external dependencies locked for stability?**

A: Yes. All external dependencies use locked versions with SRI integrity hashes to prevent breaking changes:
- **Python packages**: Pinned in `requirements.txt`
- **Fallback CDNs**: Multiple sources for resilience
- **Version detection**: Auto-adapts to API changes between major versions

See [DEPENDENCIES.md](DEPENDENCIES.md) for upgrade procedures and vendoring options for air-gapped deployments.

## Development

```bash
# Run tests
pytest tests/test_appsec.py -v
```

## Troubleshooting

```bash
# Permission issues
chmod +x start_web.sh start_cli.sh

# Dependency conflicts
rm -rf .venv && python -m venv .venv
source .venv/bin/activate && pip install -r requirements.txt

# Enable debug logging
export APPSEC_DEBUG=true
export APPSEC_LOG_LEVEL=DEBUG
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
