# IX-Guard - Security Scanner Architecture

## Project Overview

**IX-Guard** is an AI-powered security scanner that provides cross-file vulnerability analysis, tracing attack paths across multiple files and languages.

**Codebase:** 8,777 lines of Python across 20 modules. In production use.

**Key Capability:** Cross-file vulnerability analysis that traces data flow across multiple files and languages using AST parsing.

## Two Deployment Modes (All Use Same Core)

### 1. Local Mode

#### CLI - `python src/main.py`
**Target User:** Security engineers, penetration testers, local analysis
**Strengths:** Interactive repository selection, tool selection, severity level selection, detailed output, debugging capabilities
**Use Case:** "I need to scan this client's repo locally and understand the vulnerabilities"
**Tool Selection:** Choose which scanners to run: SAST (semgrep), secrets (gitleaks), dependencies (trivy), code quality linters, SBOM generation

#### Web - `python src/web_app.py`
**Target User:** Development teams, security teams, managers
**Strengths:** Visual interface with tool selection checkboxes, visual reports, team collaboration
**Use Case:** "Upload a repo and get a pretty HTML report for the team meeting"
**Tool Selection:** Interactive checkboxes allow users to select specific scanners before running scan

### 2. GitHub Actions Mode - `clients/security-scan.yml`
**Target User:** DevOps teams, automated security integration
**Strengths:** Automatic scanning, PR creation, zero maintenance, works with private repos
**Use Case:** "Scan every PR automatically and create fix PRs without human intervention"

### 3. MCP Mode - Claude Desktop Integration **INTERNAL USE**
**Target User:** Security engineers
**Strengths:** Conversational security analysis, context-aware explanations, interactive remediation
**Use Case:** "Explain this SQL injection risk and show me the fix"
**Setup:** Configure Claude Desktop MCP server at `mcp/ixguard_mcp_server.py`

## Technical Architecture Deep Dive

### Security-First Design Philosophy
- **Defense in depth** - Multiple validation layers prevent injection attacks
- **Never trust user input** - All paths, commands, and parameters are sanitized
- **Fail secure** - Errors don't expose sensitive information
- **Least privilege** - Minimal permissions required for GitHub operations

### Core Security Engine (`src/` directory)
- **`main.py`** - CLI orchestration with async/await for 60-70% performance boost
- **`web_app.py`** - Flask web interface with CORS security and input validation
- **`cross_file_analyzer.py`** - AST-based vulnerability correlation across files
- **`config.py`** - Hardcoded security constants and safe defaults
- **`exceptions.py`** - Structured error handling without information disclosure
- **`logging_config.py`** - Centralized, non-verbose logging for production use

### Scanner Integration (`src/scanners/`)
- **`semgrep.py`** - SAST with severity filtering and timeout protection
- **`gitleaks.py`** - Secret detection with false positive reduction  
- **`trivy.py`** - Dependency vulnerability scanning with version mapping
- **`validation.py`** - Shared security validation preventing code duplication

### AI-Powered Auto-Remediation (`src/auto_remediation/`)
- **Multi-provider AI**: AWS Bedrock (primary), OpenAI, Claude with fallback logic
- **Context-aware fixes**: Uses cross-file analysis for intelligent remediation
- **Separate PR strategy**: Code fixes vs dependency updates in different PRs
- **Business impact awareness**: Prioritizes fixes based on real risk assessment

### Core Technologies
- **Security Scanners**: Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies)
- **AI Integration**: AWS Bedrock (primary) with OpenAI/Claude legacy support for analysis and auto-remediation
- **Cross-File Engine**: Multi-file attack chain detection with AST parsing for 10+ languages (JavaScript, TypeScript, Python, Java, Go, Ruby, Rust, C#, PHP, Swift, Kotlin)
- **Compliance**: Automatic SBOM generation in CycloneDX and SPDX formats
- **Framework Support**: Express, React, Vue, Angular, Spring, Django, Flask, Rails, Laravel, ASP.NET

## Client Delivery Options

### Option 1: GitHub Actions (Recommended)
**Best for:** Automated CI/CD pipelines
```bash
# Client copies workflow file
cp clients/security-scan.yml .github/workflows/

# Add required GitHub secrets:
#   AWS_ACCESS_KEY_ID - IAM credentials for Bedrock
#   AWS_SECRET_ACCESS_KEY - IAM secret key
#   AWS_REGION - MUST match inference profile region (e.g., us-east-2)
#   INFERENCE_PROFILE_ID - Full ARN of Bedrock inference profile

# Push and it runs automatically
```
**Features**: Zero installation, automatic updates, PR integration
**Requirement**: Grant client read access to IX-Guard private repo

**CRITICAL:** AWS_REGION must match the region in INFERENCE_PROFILE_ID ARN or AI fixes will fail with "invalid model identifier" error.

### Option 2: Local Installation
**Best for:** Consulting engagements, ad-hoc scans

**CLI Mode (Security Professionals):**
```bash
cd src && python main.py
# → Interactive menu with severity selection
```

**Web Mode (Team Collaboration):**
```bash
python src/web_app.py
# → Opens http://localhost:8000
```
**Requirement**: Clone access to IX-Guard repo

## Core Functionality Deep Dive

### Security Analysis Pipeline
1. **Parallel Scanner Execution** (60-70% faster than sequential)
   - Semgrep: SAST analysis + code quality scanning across 10+ programming languages
   - Gitleaks: Secrets detection in code and git history
   - Trivy: Dependency vulnerabilities and CVE detection
   - Code Quality: Enabled by default (code smells, complexity, maintainability)
     - **Always reported regardless of scan level** - provides continuous value

2. **Cross-File Analysis**
   - Multi-language AST parsing for code understanding
   - Framework detection and context-aware analysis
   - Attack chain tracing across files and languages
   - Business impact assessment with cost calculations

3. **AI-Powered Auto-Remediation**
   - Context-aware code fixes using AWS Bedrock (or GPT-4/Claude legacy)
   - Deterministic by default (temperature=0.0 for consistent outputs)
   - Framework-specific remediation strategies
   - Separate PR creation for code fixes vs dependency updates
   - Manual review workflow for secrets detection

4. **Comprehensive Reporting**
   - HTML reports with executive summaries and technical details
   - Automatic SBOM generation for compliance (no configuration)
   - GitHub PR comments with Cross-File Analysis-enhanced context
   - Workflow artifacts with 90-day retention

### Auto-Remediation Modes
- **Mode 1**: SAST vulnerabilities + secret flagging (creates 1 PR)
- **Mode 2**: Dependency updates only (creates 1 PR)
- **Mode 3**: Both SAST and dependencies (creates 2 separate PRs)
- **Mode 4**: Scan only, no auto-remediation

### Scan Levels
- **critical-high** (default): Focus on actionable, high-impact **security** vulnerabilities only
  - Code quality findings are **ALWAYS included** regardless of severity
- **all**: Include all security findings (critical, high, medium, low) for comprehensive analysis
  - Code quality findings are **ALWAYS included** regardless of severity

## Configuration & Environment

### Configuration Structure Overview

**User Settings** (edit these files):
- `.env` / `env.example` (root) - API keys, feature toggles, scan levels

**Application Code** (Python constants):
- `src/config.py` - Hardcoded defaults that read from `.env` via `os.getenv()`

**External Tool Configs**:
- `configs/.gitleaks.toml` - Gitleaks secret detection rules (only config file in configs/)
- Semgrep - No config file (uses `--config auto` to download rules dynamically)

### Required Environment Variables
```bash
# AI Provider Configuration
OPENAI_API_KEY=sk-your-key-here          # OpenAI GPT-4 (legacy)
CLAUDE_API_KEY=claude-key-here           # Anthropic Claude (legacy)
AI_PROVIDER=aws_bedrock                   # 'aws_bedrock' (recommended), 'openai', or 'claude'

# Scanning Configuration
APPSEC_SCAN_LEVEL=critical-high          # 'critical-high' or 'all' (only affects security findings)
                                         # Code quality findings are ALWAYS shown when APPSEC_CODE_QUALITY=true

# Tool Selection (CLI/Web only - MCP and CI/CD always run all tools)
APPSEC_TOOLS=all                         # 'all' or comma-separated: semgrep,trivy,gitleaks,code_quality,sbom
                                         # Examples:
                                         #   all                    - Run all tools (default)
                                         #   semgrep,gitleaks       - Only SAST + secrets
                                         #   trivy                  - Only dependency scanning
                                         #   semgrep,code_quality   - SAST + code quality

APPSEC_CODE_QUALITY=true                 # Enable code quality scanning (ON by default)
APPSEC_DEBUG=false                       # Enable debug logging
APPSEC_LOG_LEVEL=INFO                    # DEBUG/INFO/WARNING/ERROR

# AI Fix Generation
APPSEC_AI_TEMPERATURE=0.0                # 0.0 = fully deterministic (recommended)

# CI/CD Auto-Remediation
APPSEC_AUTO_FIX=true                     # Enable automatic remediation
APPSEC_AUTO_FIX_MODE=3                   # 1=SAST+secrets, 2=deps, 3=both, 4=skip

# Business Configuration
SECURITY_ENGINEER_HOURLY_RATE=150       # For cost estimation calculations
```

### GitHub Actions Configuration
```yaml
# .github/workflows/security-scan.yml
uses: imaginexconsulting/appsec_scanner@v1.3.0
with:
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
  auto-fix: 'true'
  auto-fix-mode: '3'                     # Both SAST and dependencies
  fail-on-critical: 'false'              # Don't break CI by default
  scan-level: 'critical-high'
env:
  GH_TOKEN: ${{ github.token }}          # Required for PR creation
```

## Common Issues & Troubleshooting

### Workflow & CI/CD Problems
1. **No PR Creation**: 
   - Missing `GH_TOKEN: ${{ github.token }}` in workflow environment
   - Insufficient permissions: Need `contents: write` and `pull-requests: write`

2. **Permission Denied**:
   - Repository settings → Actions → General → Workflow permissions → "Read and write"
   - Check branch protection rules don't prevent bot PRs

3. **Scanner Binary Missing**:
   - Web interface auto-installs binaries
   - CLI requires manual installation: `pip install semgrep`
   - CI/CD uses pre-installed binaries in action environment

4. **API Rate Limiting**:
   - OpenAI: 3,500 requests/minute (default tier)
   - Claude: 5,000 requests/minute (default tier)
   - Enable debug logging to track API usage: `APPSEC_DEBUG=true`

### Configuration Issues
1. **Scan Level Confusion**:
   - `critical-high`: Shows only actionable, high-impact **security** vulnerabilities (critical/high)
   - `all`: Shows all **security** findings including medium/low severity
   - **Code quality findings are ALWAYS shown** regardless of scan level (when APPSEC_CODE_QUALITY=true)
   - Default is `critical-high` to avoid security noise while maintaining code quality visibility

2. **Auto-Fix Mode Selection**:
   - Mode 1: Fast, single PR for code fixes + secret flagging
   - Mode 2: Dependency updates only (safer for production)
   - Mode 3: Comprehensive, creates 2 separate PRs (recommended)
   - Mode 4: Analysis only, no auto-remediation

3. **AI Provider Selection**:
   - OpenAI GPT-4: Better for complex code analysis, slightly more expensive
   - Claude: Better for large context, cost-effective for bulk operations
   - Both support the same remediable vulnerability patterns

### Performance & Scaling
1. **Large Repository Handling**:
   - Git-aware scanning: Only scans changed files for performance
   - Memory optimization: Streaming processing for large codebases
   - Timeout configuration: Adjustable per scanner via environment variables

2. **Cross-File Analysis Analysis Performance**:
   - File analysis caching to avoid re-parsing
   - Smart prioritization: Shows 8 most critical findings
   - Framework detection optimization for faster analysis

## Testing & Validation Commands

### Local Development Testing
```bash
# Web interface (comprehensive testing)
cd src && python web_app.py
# → Open http://localhost:8000, test with sample repository

# CLI mode (detailed analysis)
cd src && python main.py
# → Follow interactive prompts, test auto-remediation

# Configuration validation
grep -r "APPSEC_" src/                   # Check configuration constants
APPSEC_DEBUG=true python main.py         # Enable debug logging
```

### API Integration Testing
```bash
# Health check
curl http://localhost:8000/health

# Scan API endpoint
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "scan_level": "critical-high"}'

# SBOM downloads
curl http://localhost:8000/reports/sbom.cyclonedx.json
curl http://localhost:8000/reports/sbom.spdx.json
```

### Scanner Output Analysis
```bash
# View raw scanner results
cat outputs/raw/semgrep.json | jq '.[] | {severity: .severity, message: .message}'
cat outputs/raw/gitleaks.json | jq '.[] | {description: .Description, file: .File}'
cat outputs/raw/trivy.json | jq '.Results[].Vulnerabilities[] | {pkg: .PkgName, severity: .Severity}'

# Check SBOM generation
ls -la outputs/sbom/
head outputs/sbom/sbom.cyclonedx.json
```

## File Structure & Key Locations

```
appsec_scanner/
├── src/                           # Core application code
│   ├── main.py                   # CLI entry point - interactive scanning
│   ├── web_app.py               # Flask web interface - team collaboration  
│   ├── cross_file_analyzer.py   # Cross-file security analysis engine
│   ├── enhanced_analyzer.py     # Cross-file enhancement layer
│   ├── config.py                # Configuration constants and validation
│   ├── exceptions.py            # Centralized error handling
│   ├── logging_config.py        # Structured logging system
│   ├── scanners/                # Individual security scanners
│   │   ├── validation.py        # Shared security validation utilities
│   │   ├── semgrep.py          # SAST scanning with timeout handling
│   │   ├── gitleaks.py         # Secrets detection with git integration
│   │   └── trivy.py            # Dependency scanning with CVE database
│   ├── auto_remediation/        # AI-powered fix generation
│   │   └── remediation.py      # Core auto-fix engine with PR creation
│   ├── reporting/              # Report generation and templates
│   │   ├── html.py             # HTML report generation with Cross-File Analysis data
│   │   └── templates/          # Jinja2 templates for reports
│   ├── templates/              # Web interface templates  
│   │   └── index.html          # Main web interface with drag-drop
│   ├── sbom_generator.py       # SBOM compliance file generation
│   └── tool_ingestion.py       # External tool integration capabilities

├── clients/                      # Client integration templates
│   ├── security-scan.yml       # Drop-in GitHub Actions workflow
│   ├── SETUP.md                # Client setup instructions
│   └── CLIENT_ENGAGEMENT_TEMPLATE.md  # Professional services guide

├── outputs/                     # Generated reports and artifacts
│   ├── report.html             # Main security analysis report
│   ├── sbom/                   # Compliance files directory
│   │   ├── sbom.cyclonedx.json # CycloneDX SBOM format
│   │   └── sbom.spdx.json      # SPDX SBOM format
│   └── raw/                    # Raw scanner JSON outputs

├── action.yml                   # GitHub Action composite action definition
├── README.md                    # User documentation and quick start
├── CHANGELOG.md                 # Version history and upgrade notes
├── main_logic.md               # Technical architecture documentation
├── requirements.txt            # Python dependencies for CLI/CI
├── requirements-web.txt        # Additional web interface dependencies
├── env.example                 # Environment variable template
└── start_web.sh               # Zero-config web interface launcher
```

## Security Implementation & Best Practices

### Input Validation & Security
- **Path Traversal Protection**: All file operations validate against directory traversal
- **Command Injection Prevention**: Parameterized commands, no shell=True usage
- **API Security**: Only vulnerability metadata sent to AI, never full source code
- **Binary Validation**: Scanner binary paths validated and sanitized
- **File Size Limits**: Prevent memory exhaustion with configurable file size limits

### Error Handling & Logging  
- **Structured Logging**: Consistent log format across all components
- **Exception Hierarchy**: Custom exception classes with detailed context
- **Security Event Logging**: All security-relevant operations logged
- **Debug Mode**: Detailed troubleshooting without exposing sensitive data

### Performance & Scalability
- **Async/Await**: 60-70% performance improvement with parallel execution
- **Caching Strategy**: File analysis and AST parsing cached for efficiency
- **Memory Management**: Streaming processing and garbage collection optimization
- **Resource Limits**: Configurable timeouts and resource constraints

## MCP (Model Context Protocol) Integration

### MCP Mode Overview
MCP enables conversational security analysis through Claude Desktop. Example queries:
- "Scan this repo and explain the SQL injection risks"
- "Show me how to fix this XSS vulnerability"
- "What's the business impact of these findings?"
- "Create PRs for the high-severity issues"

### MCP Server Architecture (`mcp/ixguard_mcp_server.py`)
Command-line execution wrapper that exposes IX-Guard functionality to Claude Desktop.

**Available MCP Tools:**
1. **`scan_repository(repo_path)`** - Full security analysis with cross-file correlation
2. **`auto_remediate(repo_path)`** - AI-powered fixes with GitHub PR creation  
3. **`get_report(repo_path)`** - Detailed vulnerability analysis and business impact
4. **`generate_sbom(repo_path)`** - Compliance-ready Software Bill of Materials
5. **`cross_file_analysis(repo_path)`** - Advanced attack chain detection
6. **`assess_business_impact(finding)`** - Context-aware risk prioritization

### Claude Desktop Setup (Critical for AI Assistants)
**Configuration file location:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%/Claude/claude_desktop_config.json`

**Minimal working config:**
```json
{
  "mcpServers": {
    "ixguard-security": {
      "command": "python",
      "args": ["/path/to/IX-Guard/mcp/ixguard_mcp_server.py"],
      "env": {
        "AI_PROVIDER": "aws_bedrock",
        "AWS_ACCESS_KEY_ID": "your_key",
        "AWS_SECRET_ACCESS_KEY": "your_secret",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

### MCP Integration Benefits
Provides conversational interface for security analysis, enabling natural language queries and explanations of findings.

## Recent Updates & Current Status

### Version 1.3.0 (Latest) - Enhanced Multi-Language Cross-File Analysis
- **Smart Finding Prioritization**: Increased from 3 to 8 most critical findings
- **Universal Framework Detection**: Enhanced detection across all supported languages
- **Real Attack Chain Detection**: AST-based data flow tracing across multiple files
- **Consolidated Reporting**: Eliminated duplicate analysis sections in reports
- **Improved Auto-Remediation Logging**: Better CI/CD debugging with detailed tracking

### Version 1.2.0 - Cross-File Analysis Integration
- **Model Context Protocol**: Real cross-file vulnerability analysis engine
- **Multi-Language AST Support**: JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin
- **Business Impact Assessment**: Context-aware risk analysis with cost estimates
- **Enhanced GitHub Integration**: Cross-File Analysis context in PR comments and descriptions

### Version 1.1.0 - Code Quality & Security
- **Shared Validation Framework**: Centralized security validation across modules
- **Structured Exception Handling**: Enhanced error management with detailed context
- **Web Interface SBOM**: Automatic compliance file generation in web mode
- **Security Hardening**: Path traversal protection and input sanitization

## Assistant Guidelines for User Interactions

### When Helping Users
1. **Environment Setup**: Always verify API keys and environment variables first
2. **Mode Selection**: Recommend web interface for teams, CLI for consultants, CI/CD for automation
3. **Troubleshooting**: Check logs first (`APPSEC_DEBUG=true`), then configuration
4. **Security**: Never log or expose API keys, use sanitized examples
5. **Performance**: For large repos, recommend `critical-high` scan level initially

### Common User Questions & Responses
**Q: "Why no vulnerabilities found?"**
A: Check scan level (`APPSEC_SCAN_LEVEL=all` to see all security findings). Note that code quality findings are always shown regardless of scan level. Verify scanners ran successfully in `outputs/raw/`

**Q: "Auto-fix not working in CI/CD?"**
A: Verify `APPSEC_AUTO_FIX=true`, check GitHub token permissions, ensure `contents: write` access

**Q: "Cross-File Analysis analysis missing?"**
A: Cross-File Analysis enhancement automatic if findings exist, check for sufficient findings to trigger analysis

**Q: "SBOM files not generated?"**
A: SBOM generation automatic in all modes, check `outputs/sbom/` directory or web interface downloads

### Debug Investigation Process
1. **Check Configuration**: Validate environment variables and API keys
2. **Review Logs**: Enable debug mode and check structured logs
3. **Scanner Status**: Verify individual scanner outputs in `outputs/raw/`
4. **Network Issues**: Check AI API connectivity and rate limits
5. **Permissions**: Verify file system and GitHub repository permissions

This comprehensive guide enables effective AI assistant support for the AppSec Scanner across all deployment modes and use cases.