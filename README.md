# AppSec-Sentinel

AI-powered security scanner with **cross-file vulnerability analysis** and **automated remediation**. Supports 10+ languages with OpenAI, Claude, and AWS Bedrock.

> 📖 **Open Source** - Licensed under the MIT License. Free for personal and commercial use.

## Features

- **Multi-Scanner Engine** - Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies) + code quality linters
- **Threat Modeling** - Automated STRIDE analysis, architecture mapping, and attack surface assessment
- **Code Quality Scanning** - ESLint, Pylint, Checkstyle, golangci-lint, RuboCop with bundled configs (no project setup needed)
- **Zero Configuration Required** - Works on any repo out-of-the-box with sensible defaults
- **Auto-Remediation** - Creates GitHub PRs with AI-generated code fixes (deterministic by default)
- **Cross-File Analysis** - Traces attack chains across multiple files and languages
- **Flexible AI Providers** - OpenAI (default), Claude, or AWS Bedrock
- **10+ Languages** - JavaScript, TypeScript, Python, Java, Go, Ruby, Rust, C#, PHP, Swift, Kotlin
- **3 Deployment Modes** - Web UI, CLI, and GitHub Actions CI/CD
- **MCP Server** - Model Context Protocol integration for Claude Desktop
- **Compliance** - Automatic SBOM generation (CycloneDX & SPDX)

## Quick Start

### What You Get Out-of-the-Box ✅

**Security scanning works immediately** - no extra installations needed:
- ✅ Semgrep (SAST) - included
- ✅ Gitleaks (secrets) - auto-detects
- ✅ Trivy (dependencies) - bundled

**Code quality scanning is optional** - install what you need:
- ESLint (JavaScript/TypeScript) - `npm install -g eslint`
- Pylint (Python) - auto-installs if missing
- Checkstyle, golangci-lint, RuboCop, Clippy, PHPStan - install as needed

> 💡 **Skip code quality?** Just ignore the "⚠️ not installed" warnings - security scanning still works perfectly!

### Prerequisites

Configure AI provider in `.env` (only needed for AI auto-remediation):
```bash
cp env.example .env
# Edit .env and set:
# AI_PROVIDER=openai
# OPENAI_API_KEY=sk-...
# AI_MODEL=gpt-5-mini
```

> 💡 **Alternative providers**: Also supports `AI_PROVIDER=claude` or `AI_PROVIDER=aws_bedrock` (see env.example for all options)

### Web Interface

```bash
./start_web.sh
# → Opens http://localhost:8000
```

**Features:**
- ✅ Tool selection via checkboxes (Semgrep, Trivy, Gitleaks, Code Quality, SBOM)
- 📊 Visual reports with executive summaries
- 📥 Download SBOM files (CycloneDX & SPDX)

### CLI Mode

```bash
./start_cli.sh
# → Interactive menu with tool selection, severity levels, and auto-fix options
```

**Features:**
- 🔧 Choose which tools to run (SAST, secrets, dependencies, code quality, SBOM)
- 🎯 Select scan level (critical-high or all)
- 🤖 Configure auto-remediation mode

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
2. **Analyze** - Cross-file analysis identifies attack chains across files
3. **Threat Model** - STRIDE analysis maps vulnerabilities to architectural threats
4. **Remediate** - AI generates fixes and creates separate PRs for code vs dependencies
5. **Report** - HTML reports + SBOM files + threat models (CycloneDX & SPDX)

## MCP Integration

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

> 💡 Credentials in `mcp/mcp_env` - no secrets in config! Install gitleaks/trivy first.

**15 MCP Tools Available:**
- **Core:** `scan_repository` • `auto_remediate` • `get_report` • `view_report_html` • `health_check`
- **Analysis:** `cross_file_analysis` • `assess_business_impact` • `generate_sbom` • `generate_threat_model`
- **API Tools:** `get_scan_findings` • `get_semgrep_findings` • `get_trivy_findings` • `get_gitleaks_findings` • `get_code_quality_findings` • `get_sbom_data`

**Usage:** "Scan nodejs-goof for vulnerabilities" → detailed findings with file paths, line numbers, remediation

[Full MCP setup guide →](mcp/README.md)

## Auto-Fix Modes
- **Mode 1**: SAST + secrets (1 PR)
- **Mode 2**: Dependencies only (1 PR)
- **Mode 3**: Both (2 separate PRs) ⭐ Recommended
- **Mode 4**: Scan only (no PRs)

## Cross-File Analysis

Traces attack paths across multiple files and languages:

- **Multi-Language AST** - Real code understanding (not regex)
- **Data Flow Tracing** - Entry points → attack paths → sensitive sinks
- **Framework-Aware** - Express, Spring, Django, Rails, Laravel, ASP.NET


## Architecture

```
Repository → [Semgrep + Gitleaks + Trivy] → Cross-File Analysis → AI (OpenAI/Claude/Bedrock) → PRs + Reports
```

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
2. Checks for repo config (.eslintrc.json, etc.) - uses it if found
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

**Zero configuration needed.** AppSec-Sentinel provides sensible defaults that work everywhere.

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

**Don't want code quality?** Set `APPSEC_CODE_QUALITY=false` in `.env` to skip entirely.

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

**Bundled Configs** (project repos don't need these):
- `configs/eslint.config.js` / `eslintrc.v8.json` - JavaScript/TypeScript
- `configs/checkstyle.xml` - Java
- `configs/golangci.yml` - Go
- `configs/rubocop.yml` - Ruby
- `configs/clippy.toml` - Rust
- `configs/phpstan.neon` - PHP
- `configs/.gitleaks.toml` - Secrets

## Documentation

- **[Threat Modeling](THREAT_MODELING.md)** - Automated threat analysis using STRIDE framework
- **[MCP Setup](mcp/README.md)** - Model Context Protocol integration
- **[Project Setup](projects/SETUP.md)** - Project onboarding guide
- **[Architecture](ARCHITECTURE.md)** - System architecture and design patterns

## FAQ

**Q: What's the MCP "custom" server doing?**

A: Exposes 6 security tools to Claude Desktop - domain-specific security functions (scan, analyze attack chains, auto-remediate, generate SBOM). Enables conversational security analysis.

**Q: How do I trust AI-generated fixes?**

A: PRs require manual review before merge. Separate PRs for code fixes vs dependencies. Conservative patterns only (SQLi, XSS, input validation). Your tests still validate. 70-80% are safe after quick review.

**Q: What data goes to the AI provider?**

A: Vulnerability metadata, file names, line numbers, code snippets. Never full codebases. Secrets flagged locally, never sent to AI.

**Q: GitHub Actions vs MCP vs CLI vs Web?**

A: Actions = automated PR scans. MCP = conversational analysis with Claude. CLI = consultant deep-dive. Web = team reports. Use what fits your workflow.

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
