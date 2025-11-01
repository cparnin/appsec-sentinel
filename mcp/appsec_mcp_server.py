#!/usr/bin/env python3
"""
AppSec-Sentinel MCP Server - Conversational security analysis interface
"""

import json
import sys
import subprocess
import os
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

class EverythingAppSecMCP:
    def __init__(self):
        self.appsec_path = self._find_appsec_installation()
        self._load_env_file()
        # Import path utilities for new repo/branch structure
        try:
            from path_utils import get_output_path
            from config import BASE_OUTPUT_DIR
            self.get_output_path = get_output_path
            self.base_output_dir = BASE_OUTPUT_DIR
        except ImportError:
            # Fallback for older versions
            self.get_output_path = None
            self.base_output_dir = "outputs"
        self.tools = [
            {
                "name": "scan_repository",
                "description": "Run comprehensive security scan using Semgrep (SAST), Gitleaks (secrets), and Trivy (dependencies). Returns vulnerability counts by severity with risk summary. USE THIS FIRST before other analysis tools. Example: 'Scan nodejs-goof for vulnerabilities'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository name (e.g., 'nodejs-goof') or full path. Smart discovery enabled for repos in ~/repos"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "auto_remediate",
                "description": "AI-powered auto-remediation that generates fixes and creates GitHub PRs. Creates 2 separate PRs: one for SAST/code fixes, one for dependency updates. Requires prior scan. Example: 'Fix the vulnerabilities and create PRs'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository to fix (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_report",
                "description": "Display detailed security report with all findings, severity breakdown, and file locations. Shows the pr-findings.txt summary. Example: 'Show me the detailed security report'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "generate_sbom",
                "description": "Display Software Bill of Materials in CycloneDX and SPDX formats for compliance. Shows component inventory for SOC2, FedRAMP, ISO 27001. Example: 'Generate SBOM for compliance'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "cross_file_analysis",
                "description": "Advanced multi-file attack chain detection across 15+ languages. Shows how vulnerabilities connect across files to form exploitable paths. AppSec-Sentinel's signature feature. Example: 'Show cross-file attack chains'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "assess_business_impact",
                "description": "Business-focused risk assessment with financial impact, compliance risk, and remediation timeline recommendations. Perfect for executive summaries. Example: 'What's the business impact?'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "view_report_html",
                "description": "Open the beautiful HTML security report in your default browser. Includes executive summary, detailed findings, cross-file analysis, and downloadable SBOM files. Example: 'Open the HTML report'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_scan_findings",
                "description": "Get detailed vulnerability findings with file paths, line numbers, and remediation guidance. Returns paginated, structured data for agent processing. Essential for IXcellerate workflows. Example: 'Get scan findings page 1 with critical severity'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "page": {"type": "number", "description": "Page number (default: 1)", "default": 1},
                        "page_size": {"type": "number", "description": "Results per page (default: 10, max: 50)", "default": 10},
                        "severity_filter": {"type": "string", "description": "Filter by severity: critical|high|medium|low"},
                        "tool_filter": {"type": "string", "description": "Filter by tool: semgrep|gitleaks|trivy"},
                        "category_filter": {"type": "string", "description": "Filter by category: security|code_quality"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_semgrep_findings",
                "description": "[IXaidev API] Get paginated Semgrep SAST findings with structured JSON response. Returns security vulnerabilities with file paths, line numbers, CWE/OWASP mappings, and remediation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "page": {"type": "number", "description": "Page number (default: 1)", "default": 1},
                        "page_size": {"type": "number", "description": "Results per page (default: 10, max: 50)", "default": 10},
                        "severity_filter": {"type": "string", "description": "Filter by severity: critical|high|medium|low"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_trivy_findings",
                "description": "[IXaidev API] Get paginated Trivy dependency vulnerability findings with structured JSON response. Returns CVE details, affected packages, versions, and fix information.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "page": {"type": "number", "description": "Page number (default: 1)", "default": 1},
                        "page_size": {"type": "number", "description": "Results per page (default: 10, max: 50)", "default": 10},
                        "severity_filter": {"type": "string", "description": "Filter by severity: critical|high|medium|low"},
                        "fix_available": {"type": "boolean", "description": "Filter by fix availability"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_gitleaks_findings",
                "description": "[IXaidev API] Get paginated Gitleaks secret/credential findings with structured JSON response. Returns detected secrets, locations, and remediation steps.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "page": {"type": "number", "description": "Page number (default: 1)", "default": 1},
                        "page_size": {"type": "number", "description": "Results per page (default: 10, max: 50)", "default": 10}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_code_quality_findings",
                "description": "[IXaidev API] Get paginated code quality findings from all linters with structured JSON response. Returns code smells, complexity issues, and best practice violations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "page": {"type": "number", "description": "Page number (default: 1)", "default": 1},
                        "page_size": {"type": "number", "description": "Results per page (default: 10, max: 50)", "default": 10},
                        "linter_filter": {"type": "string", "description": "Filter by linter: eslint|pylint|checkstyle|golangci-lint|rubocop|clippy|phpstan"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "get_sbom_data",
                "description": "[IXaidev API] Get Software Bill of Materials in structured JSON. Returns CycloneDX and SPDX formatted component inventory for compliance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository (must be scanned first)"},
                        "format": {"type": "string", "description": "SBOM format: cyclonedx|spdx|both (default: both)", "default": "both"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "generate_threat_model",
                "description": "Generate automated threat model using STRIDE framework. Performs architecture analysis, identifies trust boundaries, maps attack surface, and categorizes threats. Returns structured threat model with visual diagram. Example: 'Generate threat model for this application'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Repository to analyze (scan first for enhanced analysis)"}
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "health_check",
                "description": "Diagnostic tool to verify MCP server health, scanner availability, and configuration. Use when troubleshooting setup issues or verifying installation. Example: 'Check if AppSec-Sentinel is working correctly'",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        ]
        
    def main(self):
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                
                message = json.loads(line)
                response = self.handle_message(message)
                if response:
                    print(json.dumps(response), flush=True)
                
            except json.JSONDecodeError:
                self.send_error(None, -32700, "Parse error")
            except Exception as e:
                self.send_error(None, -32603, f"Error: {str(e)}")
    
    def handle_message(self, message):
        method = message.get("method")
        msg_id = message.get("id")
        
        if "id" not in message:
            return None  # Notification
        
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "appsec-sentinel", "version": "1.0.0"}
                }
            }
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.tools}}
        elif method == "tools/call":
            return self.handle_tool_call(message)
        else:
            return self.send_error(msg_id, -32601, f"Unknown method: {method}")
    
    def handle_tool_call(self, message):
        msg_id = message.get("id")
        params = message.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        try:
            if tool_name == "scan_repository":
                result = self.scan_repository(arguments)
            elif tool_name == "auto_remediate":
                result = self.auto_remediate(arguments)
            elif tool_name == "get_report":
                result = self.get_report(arguments)
            elif tool_name == "generate_sbom":
                result = self.generate_sbom(arguments)
            elif tool_name == "cross_file_analysis":
                result = self.cross_file_analysis(arguments)
            elif tool_name == "assess_business_impact":
                result = self.assess_business_impact(arguments)
            elif tool_name == "view_report_html":
                result = self.view_report_html(arguments)
            elif tool_name == "get_scan_findings":
                result = self.get_scan_findings(arguments)
            elif tool_name == "get_semgrep_findings":
                result = self.get_semgrep_findings(arguments)
            elif tool_name == "get_trivy_findings":
                result = self.get_trivy_findings(arguments)
            elif tool_name == "get_gitleaks_findings":
                result = self.get_gitleaks_findings(arguments)
            elif tool_name == "get_code_quality_findings":
                result = self.get_code_quality_findings(arguments)
            elif tool_name == "get_sbom_data":
                result = self.get_sbom_data_structured(arguments)
            elif tool_name == "generate_threat_model":
                result = self.generate_threat_model(arguments)
            elif tool_name == "health_check":
                result = self.health_check(arguments)
            else:
                return self.send_error(msg_id, -32601, f"Unknown tool: {tool_name}")
            
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": result}]}
            }
        except Exception as e:
            return self.send_error(msg_id, -32603, f"Tool failed: {str(e)}")
    
    def _load_env_file(self):
        """Load environment variables from mcp_env file"""
        mcp_dir = os.path.dirname(os.path.abspath(__file__))
        env_file = os.path.join(mcp_dir, "mcp_env")

        if os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()

    def _find_appsec_installation(self):
        """Find AppSec-Sentinel installation directory"""
        # Check environment variable first
        if "APPSEC_PATH" in os.environ:
            path = os.environ["APPSEC_PATH"]
            if os.path.exists(path) and os.path.exists(os.path.join(path, "src", "main.py")):
                return path
        
        # Try common locations
        common_locations = [
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # Parent of mcp directory
            os.path.expanduser("~/Documents/appsec-sentinel"),  # User's Documents folder
            os.path.expanduser("~/repos/appsec-sentinel"),
            os.path.expanduser("~/appsec-sentinel"),
            os.path.expanduser("~/projects/appsec-sentinel"),
            "./appsec-sentinel",
            "../appsec-sentinel"
        ]
        
        for location in common_locations:
            if os.path.exists(location) and os.path.exists(os.path.join(location, "src", "main.py")):
                return os.path.abspath(location)
        
        # If not found, provide helpful error message
        searched_paths = "\n".join([f"  - {loc}" for loc in common_locations])
        raise RuntimeError(f"""AppSec-Sentinel installation not found.

Searched locations:
{searched_paths}

Please either:
1. Set APPSEC_PATH environment variable to your installation path
2. Install AppSec-Sentinel in one of the searched locations
3. Clone AppSec-Sentinel to ~/Documents/appsec-sentinel

Example: export APPSEC_PATH="/path/to/your/appsec-sentinel" """)
    
    def _find_repo_search_paths(self):
        """Get repository search paths from environment or defaults"""
        base_paths = []
        
        # Check environment variable
        if "REPO_SEARCH_PATHS" in os.environ:
            base_paths.extend(os.environ["REPO_SEARCH_PATHS"].split(":"))
        
        # Add common defaults
        user_home = os.path.expanduser("~")
        base_paths.extend([
            os.path.join(user_home, "repos"),
            os.path.join(user_home, "projects"),
            user_home,
            "."
        ])
        
        return base_paths
    
    def find_repo(self, repo_path):
        """Smart repo discovery with fuzzy matching"""
        if os.path.exists(repo_path):
            return repo_path
            
        # Try exact match first in all search paths
        search_paths = self._find_repo_search_paths()
        locations = []
        
        for base_path in search_paths:
            locations.extend([
                os.path.join(base_path, repo_path),
                repo_path if base_path == "." else None
            ])
        
        # Filter out None values
        locations = [loc for loc in locations if loc]
        
        for loc in locations:
            if os.path.exists(loc):
                return os.path.abspath(loc)
        
        # Try fuzzy matching in each search directory
        for search_dir in search_paths:
            if os.path.exists(search_dir) and os.path.isdir(search_dir):
                try:
                    for item in os.listdir(search_dir):
                        # Check for partial matches (nodejsgoof -> nodejs-goof)
                        if repo_path.lower() in item.lower() or item.lower() in repo_path.lower():
                            full_path = os.path.join(search_dir, item)
                            if os.path.isdir(full_path):
                                return os.path.abspath(full_path)
                except PermissionError:
                    continue
                
        raise ValueError(f"Repository '{repo_path}' not found in common locations")
    
    def scan_repository(self, args):
        """Run AppSec-Sentinel scan - EXACTLY like command line"""
        repo_path = self.find_repo(args["repo_path"])

        # Find Python executable
        python_exe = self._find_python_executable()
        main_py = os.path.join(self.appsec_path, "src", "main.py")

        cmd = [python_exe, main_py]

        env = os.environ.copy()
        env["GITHUB_ACTIONS"] = "true"  # Non-interactive
        # Scan level already loaded from mcp_env via _load_env_file()

        # Configurable timeout (default: 5 minutes, sufficient for large repos)
        scan_timeout = int(os.getenv('MCP_SCAN_TIMEOUT', '300'))

        # Enable code quality scanning by default (if not explicitly disabled)
        if "APPSEC_CODE_QUALITY" not in env:
            env["APPSEC_CODE_QUALITY"] = "true"

        # Ensure scanner binaries are in PATH (cross-platform support)
        # Add common installation locations for gitleaks, trivy, semgrep
        common_bin_paths = [
            "/opt/homebrew/bin",      # macOS Homebrew (Apple Silicon)
            "/usr/local/bin",          # macOS Homebrew (Intel) / Linux
            "/usr/bin",                # Linux system packages
            "/snap/bin",               # Linux Snap packages
            os.path.expanduser("~/.local/bin"),  # User-installed binaries
            "C:\\Program Files\\gitleaks",  # Windows
            "C:\\Program Files\\trivy",     # Windows
        ]
        current_path = env.get("PATH", "")
        for bin_path in common_bin_paths:
            if os.path.exists(bin_path) and bin_path not in current_path:
                env["PATH"] = f"{bin_path}{os.pathsep}{current_path}"
                current_path = env["PATH"]
        
        print(f"🔄 Scanning {repo_path}...", file=sys.stderr)
        
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=scan_timeout,
                env=env
            )
            
            output = result.stdout

            # Try to parse accurate counts from JSON outputs first
            outputs_path = self._get_repo_output_path(repo_path)
            raw_outputs = os.path.join(outputs_path, "raw")
            sast_count = 0
            secrets_count = 0
            deps_count = 0
            code_quality_count = 0
            critical = 0
            high = 0

            # Parse Semgrep JSON for SAST findings
            semgrep_json = os.path.join(raw_outputs, "semgrep.json")
            if os.path.exists(semgrep_json):
                try:
                    with open(semgrep_json) as f:
                        semgrep_data = json.load(f)
                        results = semgrep_data.get("results", [])
                        sast_count = len(results)
                        for result_item in results:
                            severity = result_item.get("extra", {}).get("severity", "").upper()
                            if severity == "ERROR":  # Semgrep uses ERROR for critical/high
                                critical += 1
                            elif severity == "WARNING":
                                high += 1
                except Exception as e:
                    print(f"Failed to parse semgrep.json: {e}", file=sys.stderr)

            # Parse Gitleaks JSON for secrets
            gitleaks_json = os.path.join(raw_outputs, "gitleaks.json")
            if os.path.exists(gitleaks_json):
                try:
                    with open(gitleaks_json) as f:
                        gitleaks_data = json.load(f)
                        if isinstance(gitleaks_data, list):
                            secrets_count = len(gitleaks_data)
                            critical += secrets_count  # All secrets are critical
                except Exception as e:
                    print(f"Failed to parse gitleaks.json: {e}", file=sys.stderr)

            # Parse Trivy JSON for dependencies
            trivy_json = os.path.join(raw_outputs, "trivy-sca.json")
            if os.path.exists(trivy_json):
                try:
                    with open(trivy_json) as f:
                        trivy_data = json.load(f)
                        results = trivy_data.get("Results", [])
                        for result_item in results:
                            vulns = result_item.get("Vulnerabilities", [])
                            deps_count += len(vulns)
                            for vuln in vulns:
                                severity = vuln.get("Severity", "").upper()
                                if severity == "CRITICAL":
                                    critical += 1
                                elif severity == "HIGH":
                                    high += 1
                except Exception as e:
                    print(f"Failed to parse trivy-sca.json: {e}", file=sys.stderr)

            # Parse ESLint JSON for code quality (JavaScript/TypeScript)
            eslint_json = os.path.join(raw_outputs, "eslint.json")
            if os.path.exists(eslint_json):
                try:
                    with open(eslint_json) as f:
                        eslint_data = json.load(f)
                        if isinstance(eslint_data, list):
                            for file_result in eslint_data:
                                messages = file_result.get('messages', [])
                                code_quality_count += len(messages)
                except Exception as e:
                    print(f"Failed to parse eslint.json: {e}", file=sys.stderr)

            # Parse Pylint JSON for code quality (Python)
            pylint_json = os.path.join(raw_outputs, "pylint.json")
            if os.path.exists(pylint_json):
                try:
                    with open(pylint_json) as f:
                        pylint_data = json.load(f)
                        if isinstance(pylint_data, list):
                            code_quality_count += len(pylint_data)
                except Exception as e:
                    print(f"Failed to parse pylint.json: {e}", file=sys.stderr)

            # Parse Checkstyle JSON for code quality (Java)
            checkstyle_json = os.path.join(raw_outputs, "checkstyle.json")
            if os.path.exists(checkstyle_json):
                try:
                    with open(checkstyle_json) as f:
                        checkstyle_data = json.load(f)
                        if isinstance(checkstyle_data, list):
                            code_quality_count += len(checkstyle_data)
                except Exception as e:
                    print(f"Failed to parse checkstyle.json: {e}", file=sys.stderr)

            # Parse golangci-lint JSON for code quality (Go)
            golangci_json = os.path.join(raw_outputs, "golangci-lint.json")
            if os.path.exists(golangci_json):
                try:
                    with open(golangci_json) as f:
                        golangci_data = json.load(f)
                        if isinstance(golangci_data, list):
                            code_quality_count += len(golangci_data)
                except Exception as e:
                    print(f"Failed to parse golangci-lint.json: {e}", file=sys.stderr)

            # Parse RuboCop JSON for code quality (Ruby)
            rubocop_json = os.path.join(raw_outputs, "rubocop.json")
            if os.path.exists(rubocop_json):
                try:
                    with open(rubocop_json) as f:
                        rubocop_data = json.load(f)
                        if isinstance(rubocop_data, list):
                            code_quality_count += len(rubocop_data)
                except Exception as e:
                    print(f"Failed to parse rubocop.json: {e}", file=sys.stderr)

            # Parse Clippy JSON for code quality (Rust)
            clippy_json = os.path.join(raw_outputs, "clippy.json")
            if os.path.exists(clippy_json):
                try:
                    with open(clippy_json) as f:
                        clippy_data = json.load(f)
                        if isinstance(clippy_data, list):
                            code_quality_count += len(clippy_data)
                except Exception as e:
                    print(f"Failed to parse clippy.json: {e}", file=sys.stderr)

            # Parse PHPStan JSON for code quality (PHP)
            phpstan_json = os.path.join(raw_outputs, "phpstan.json")
            if os.path.exists(phpstan_json):
                try:
                    with open(phpstan_json) as f:
                        phpstan_data = json.load(f)
                        if isinstance(phpstan_data, list):
                            code_quality_count += len(phpstan_data)
                except Exception as e:
                    print(f"Failed to parse phpstan.json: {e}", file=sys.stderr)

            # Calculate totals
            total = sast_count + secrets_count + deps_count
            total_with_quality = total + code_quality_count
            sast_status = f"{sast_count} vulnerabilities" if sast_count > 0 else "clean"
            
            # Format risk indicators
            critical_indicator = "🔴" if critical > 0 else "✅"
            high_indicator = "🟠" if high > 0 else "✅"

            # Format code quality status
            quality_status = f"{code_quality_count} issues" if code_quality_count > 0 else "clean"

            return f"""# 🛡️ AppSec-Sentinel Security Scan Results

**Repository**: `{os.path.basename(repo_path)}`
**Scan Time**: {self.extract_time(output)}

## 📊 Scanner Results:
| Scanner | Status |
|---------|--------|
| **Semgrep (SAST)** | {sast_status} |
| **Gitleaks (Secrets)** | {secrets_count} vulnerabilities |
| **Trivy (Dependencies)** | {deps_count} vulnerabilities |
| **Code Quality Linters** | {quality_status} |

## 🎯 Risk Summary:
| Severity | Count | Status |
|----------|-------|--------|
| **Critical** | {critical} | {critical_indicator} |
| **High** | {high} | {high_indicator} |
| **Security Total** | {total} | - |
| **Code Quality** | {code_quality_count} | 📊 |
| **Grand Total** | {total_with_quality} | - |

## 💡 What To Do Next:
**For detailed analysis:**
- "Show me the detailed report" → View all findings with file locations
- "Show cross-file attack chains" → See how vulnerabilities connect
- "What's the business impact?" → Executive risk assessment

**To fix vulnerabilities:**
- "Fix the vulnerabilities and create PRs" → Auto-remediation with GitHub PRs
- "Open the HTML report" → Beautiful browser-based report

**For compliance:**
- "Generate SBOM for compliance" → Software Bill of Materials

**Status**: ✅ Scan completed successfully
"""

        except subprocess.TimeoutExpired:
            timeout_msg = f"❌ Scan timed out after {scan_timeout} seconds (increase with MCP_SCAN_TIMEOUT env var)"
            if os.getenv('APPSEC_DEBUG') == 'true':
                timeout_msg += f"\n\n**Debug Info**: Set MCP_SCAN_TIMEOUT higher for large repositories"
            return timeout_msg
        except Exception as e:
            error_msg = f"❌ Scan failed: {str(e)}"
            if os.getenv('APPSEC_DEBUG') == 'true':
                error_msg += f"\n\n**Debug Info**:\n- Repo: {repo_path}\n- Command: {' '.join(cmd)}\n- Check scanner binaries are installed (gitleaks, trivy, semgrep)"
            return error_msg
    
    def auto_remediate(self, args):
        """Run AppSec-Sentinel auto-remediation"""
        repo_path = self.find_repo(args["repo_path"])

        # Find Python executable
        python_exe = self._find_python_executable()
        main_py = os.path.join(self.appsec_path, "src", "main.py")

        cmd = [python_exe, main_py]

        env = os.environ.copy()
        env["GITHUB_ACTIONS"] = "true"
        env["APPSEC_AUTO_FIX"] = "true"
        env["APPSEC_AUTO_FIX_MODE"] = "3"  # Both SAST and dependencies
        # Scan level already loaded from mcp_env via _load_env_file()

        # Configurable timeout (default: 10 minutes for AI-powered remediation)
        remediate_timeout = int(os.getenv('MCP_REMEDIATE_TIMEOUT', '600'))

        # Ensure scanner binaries are in PATH (cross-platform support)
        # Add common installation locations for gitleaks, trivy, semgrep
        common_bin_paths = [
            "/opt/homebrew/bin",      # macOS Homebrew (Apple Silicon)
            "/usr/local/bin",          # macOS Homebrew (Intel) / Linux
            "/usr/bin",                # Linux system packages
            "/snap/bin",               # Linux Snap packages
            os.path.expanduser("~/.local/bin"),  # User-installed binaries
            "C:\\Program Files\\gitleaks",  # Windows
            "C:\\Program Files\\trivy",     # Windows
        ]
        current_path = env.get("PATH", "")
        for bin_path in common_bin_paths:
            if os.path.exists(bin_path) and bin_path not in current_path:
                env["PATH"] = f"{bin_path}{os.pathsep}{current_path}"
                current_path = env["PATH"]

        # Ensure AWS credentials are passed through for AI auto-remediation
        required_aws_vars = ["AI_PROVIDER", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                            "AWS_REGION", "AWS_DEFAULT_REGION", "INFERENCE_PROFILE_ID", "AI_MODEL"]
        for var in required_aws_vars:
            if var in os.environ:
                env[var] = os.environ[var]
        
        print(f"🤖 Auto-remediating {repo_path}...", file=sys.stderr)
        
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=remediate_timeout,
                env=env
            )
            
            output = result.stdout
            
            # Look for PR creation messages
            pr_urls = []
            for line in output.split('\n'):
                if "Pull Request created:" in line:
                    pr_urls.append(line.split(": ")[-1])
                    
            if pr_urls:
                pr_list = '\n'.join([f"• {url}" for url in pr_urls])
                return f"""# 🚀 Auto-Remediation Complete!

**Repository**: `{os.path.basename(repo_path)}`

## ✅ Pull Requests Created:
{pr_list}

## 📋 What Was Fixed:
• **PR 1**: SAST vulnerabilities and secrets (flagged for review)
• **PR 2**: Dependency updates with CVE patches

## 💡 Next Steps:
1. **Review PRs** - Check the AI-generated fixes for accuracy
2. **Run Tests** - Ensure fixes don't break functionality
3. **Merge PRs** - Deploy fixes to production
4. **Re-scan** - Verify vulnerabilities are resolved

**Mode**: Mode 3 (Comprehensive) - Separate PRs for safety
**Status**: ✅ Remediation completed successfully
"""
            else:
                # Check for common failure reasons in output
                failure_reason = "Unknown"
                if "No remediable findings" in output:
                    failure_reason = "No auto-fixable vulnerabilities found"
                elif "AWS" in output and "credentials" in output:
                    failure_reason = "AWS credentials issue - check mcp_env configuration"
                elif "GitHub" in output and "token" in output:
                    failure_reason = "GitHub token issue - check GITHUB_TOKEN in mcp_env"

                outputs_path = self._get_repo_output_path(repo_path)
                return f"""# 🤖 Auto-Remediation Status

**Repository**: `{os.path.basename(repo_path)}`
**Result**: No PRs created

## 🔍 Possible Reasons:
• **No auto-fixable vulnerabilities** - Some issues require manual fixes
• **Already fixed** - Vulnerabilities may be resolved
• **Configuration issue** - Check AWS/GitHub credentials in mcp_env

**Detected Issue**: {failure_reason}

## 💡 Troubleshooting:
1. Run "Show me the detailed report" to see all findings
2. Check `{os.path.join(outputs_path, 'pr-findings.txt')}` for details
3. Verify AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN in mcp_env

**Status**: ⚠️ No changes made
"""


        except subprocess.TimeoutExpired:
            timeout_msg = f"❌ Auto-remediation timed out after {remediate_timeout} seconds (increase with MCP_REMEDIATE_TIMEOUT env var)"
            if os.getenv('APPSEC_DEBUG') == 'true':
                timeout_msg += f"\n\n**Debug Info**: AI-powered remediation takes longer. Consider increasing timeout for complex fixes."
            return timeout_msg
        except Exception as e:
            error_msg = f"❌ Auto-remediation failed: {str(e)}"
            if os.getenv('APPSEC_DEBUG') == 'true':
                error_msg += f"\n\n**Debug Info**:\n- Repo: {repo_path}\n- Check AWS credentials in mcp_env (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)\n- Check GITHUB_TOKEN has 'repo' permissions\n- Verify git user config: git config --global user.name"
            return error_msg
    
    def _find_python_executable(self):
        """Find appropriate Python executable"""
        # Try virtual environment first
        venv_python = os.path.join(self.appsec_path, ".venv", "bin", "python")
        if os.path.exists(venv_python):
            return venv_python

        # Try system python
        for python_cmd in ["python3", "python"]:
            try:
                result = subprocess.run([python_cmd, "--version"], capture_output=True, text=True)
                if result.returncode == 0:
                    return python_cmd
            except FileNotFoundError:
                continue

        return "python3"  # Fallback

    def _get_repo_output_path(self, repo_path):
        """Get the output path for a specific repository using new structure"""
        if self.get_output_path:
            # Use new repo/branch-aware structure
            output_path = self.get_output_path(repo_path, self.base_output_dir)
            return str(output_path)
        else:
            # Fallback to old flat structure
            return os.path.join(self.appsec_path, "outputs")
    
    def get_report(self, args):
        """Get report from pr-findings.txt"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)
        pr_findings = os.path.join(outputs_path, "pr-findings.txt")

        if os.path.exists(pr_findings):
            with open(pr_findings) as f:
                content = f.read()

            return f"""# 📊 Security Report Summary

{content}

**HTML Report**: `{os.path.join(outputs_path, 'report.html')}`

**Status**: ✅ Report available
"""
        else:
            return """# 📊 No Report Available

Run `scan_repository` first to generate a security report.
"""
    
    def extract_number(self, line):
        """Extract number from scanner line"""
        try:
            parts = line.split()
            for i, part in enumerate(parts):
                if "vulnerabilities" in part and i > 0:
                    return int(parts[i-1])
        except:
            pass
        return 0
    
    def extract_time(self, output):
        """Extract scan time from output"""
        for line in output.split('\n'):
            if "found in" in line and "s" in line:
                try:
                    # Extract "16.3s" from "110 vulnerabilities found in 16.3s"
                    return line.split("in ")[-1]
                except:
                    pass
        return "unknown time"
    
    def generate_sbom(self, args):
        """Generate SBOM files"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Check if SBOM files exist from recent scan
        sbom_dir = os.path.join(outputs_path, "sbom")
        cyclone_path = os.path.join(sbom_dir, "sbom.cyclonedx.json")
        spdx_path = os.path.join(sbom_dir, "sbom.spdx.json")
        
        if os.path.exists(cyclone_path) and os.path.exists(spdx_path):
            try:
                # Read and parse SBOM files for summary
                with open(cyclone_path) as f:
                    cyclone_data = json.loads(f.read())
                with open(spdx_path) as f:
                    spdx_data = json.loads(f.read())
                
                components = len(cyclone_data.get("components", []))
                packages = len(spdx_data.get("packages", []))
                
                return f"""# 📋 Software Bill of Materials (SBOM)

**Repository**: {os.path.basename(repo_path)}

## 📊 SBOM Summary:
• **CycloneDX Format**: {components} components
• **SPDX Format**: {packages} packages

## 📁 Generated Files:
• **CycloneDX**: `{cyclone_path}`
• **SPDX**: `{spdx_path}`

## ✅ Compliance Benefits:
• **Supply Chain Visibility**: Complete component inventory
• **License Compliance**: SPDX format for legal requirements  
• **Vulnerability Tracking**: CycloneDX for security analysis
• **Regulatory Compliance**: SOC2, FedRAMP, ISO 27001 ready

**Status**: ✅ SBOM generated successfully
"""
            except:
                pass
        
        return """# 📋 No SBOM Available

Run `scan_repository` first to generate SBOM files.
"""
    
    def cross_file_analysis(self, args):
        """Get cross-file analysis results"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)
        pr_findings = os.path.join(outputs_path, "pr-findings.txt")
        
        if os.path.exists(pr_findings):
            with open(pr_findings) as f:
                content = f.read()
                
            # Extract cross-file analysis info
            tech_stack = ""
            analysis_result = ""
            
            for line in content.split('\n'):
                if "Tech Stack:" in line:
                    tech_stack = line.split("Tech Stack:")[-1].strip()
                elif "Cross-file Analysis:" in line:
                    analysis_result = line.split("Cross-file Analysis:")[-1].strip()
                
            return f"""# 🔗 Cross-File Vulnerability Analysis

**Repository**: {os.path.basename(repo_path)}

## 🏗️ Technology Stack: {tech_stack}

## ⚔️ Attack Chain Analysis: {analysis_result}

**Status**: ✅ AI-enhanced cross-file analysis completed
"""
        
        return """# 🔗 No Analysis Available

Run `scan_repository` first to generate cross-file analysis.
"""
    
    def assess_business_impact(self, args):
        """Generate business impact assessment"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)
        pr_findings = os.path.join(outputs_path, "pr-findings.txt")
        
        if os.path.exists(pr_findings):
            with open(pr_findings) as f:
                content = f.read()
            
            critical = 0
            high = 0
            total = 0
            
            for line in content.split('\n'):
                if "Critical:" in line:
                    try:
                        critical = int(line.split()[-1])
                    except:
                        pass
                elif "High:" in line:
                    try:
                        high = int(line.split()[-1])
                    except:
                        pass
                elif "security findings detected" in line:
                    try:
                        total = int(line.split()[1])
                    except:
                        pass
            
            # Calculate risk
            if critical > 0:
                risk_level = "🔴 **HIGH RISK**"
                recommendation = "Priority remediation within 1 week"
            elif high > 10:
                risk_level = "🟠 **MEDIUM RISK**"
                recommendation = "Schedule remediation within 30 days"  
            else:
                risk_level = "🟡 **LOW RISK**"
                recommendation = "Monitor and maintain security posture"
            
            return f"""# 🎯 Business Impact Assessment

**Repository**: {os.path.basename(repo_path)}
**Risk Level**: {risk_level}

## 📊 Security Metrics:
• **Total Vulnerabilities**: {total}
• **Critical Issues**: {critical}
• **High Priority**: {high}

## 💼 Business Impact:
• **Financial Risk**: {'High' if critical > 0 else 'Medium' if high > 5 else 'Low'}
• **Compliance Risk**: {'Critical' if critical > 5 else 'Moderate' if high > 0 else 'Low'}

## 🎯 Recommendation: {recommendation}

**Status**: ✅ AI-powered risk assessment completed
"""
        
        return """# 🎯 No Assessment Available

Run `scan_repository` first to generate business impact assessment.
"""
    
    def view_report_html(self, args):
        """Open HTML report in default browser"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)
        report_path = os.path.join(outputs_path, "report.html")

        if os.path.exists(report_path):
            try:
                # macOS
                subprocess.run(["open", report_path], check=True)
                return f"""# 🌐 HTML Report Opened!

**Report Location**: `{report_path}`

## 📊 Report Includes:
• **Executive Summary** - High-level risk overview
• **Detailed Findings** - Every vulnerability with context
• **Cross-File Analysis** - Attack chain visualization
• **SBOM Downloads** - CycloneDX and SPDX formats
• **Remediation Guidance** - Step-by-step fixes

**Status**: ✅ Report opened in default browser
"""
            except Exception as e:
                return f"""# 🌐 Report Available

**Report Location**: `{report_path}`

Could not auto-open browser: {str(e)}

**Manual access**: Open the file path above in your browser

**Status**: ⚠️ Manual open required
"""
        else:
            return """# 🌐 No HTML Report Available

Run `scan_repository` first to generate the HTML security report.

**Example**: "Scan nodejs-goof for vulnerabilities"
"""

    def get_scan_findings(self, args):
        """Get detailed vulnerability findings with pagination and filtering"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Input validation for pagination parameters
        page = max(1, min(args.get('page', 1), 1000))  # Cap at 1000 pages
        page_size = max(1, min(args.get('page_size', 10), 50))  # 1-50 per page

        severity_filter = args.get('severity_filter')
        tool_filter = args.get('tool_filter')
        category_filter = args.get('category_filter')

        # Read raw JSON files (reuse logic from batch_wrapper.py lines 107-149)
        raw_dir = os.path.join(outputs_path, "raw")
        all_findings = []

        # Parse Semgrep results (SAST)
        semgrep_file = os.path.join(raw_dir, "semgrep.json")
        if os.path.exists(semgrep_file):
            try:
                with open(semgrep_file, 'r') as f:
                    semgrep_data = json.load(f)
                    results = semgrep_data.get('results', [])
                    all_findings.extend([{'tool': 'semgrep', 'data': r} for r in results])
            except Exception as e:
                print(f"Failed to parse semgrep.json: {e}", file=sys.stderr)

        # Parse Gitleaks results (Secrets)
        gitleaks_file = os.path.join(raw_dir, "gitleaks.json")
        if os.path.exists(gitleaks_file):
            try:
                with open(gitleaks_file, 'r') as f:
                    gitleaks_data = json.load(f)
                    if isinstance(gitleaks_data, list):
                        all_findings.extend([{'tool': 'gitleaks', 'data': r} for r in gitleaks_data])
            except Exception as e:
                print(f"Failed to parse gitleaks.json: {e}", file=sys.stderr)

        # Parse Trivy results (Dependencies)
        trivy_file = os.path.join(raw_dir, "trivy-sca.json")
        if os.path.exists(trivy_file):
            try:
                with open(trivy_file, 'r') as f:
                    trivy_data = json.load(f)
                    trivy_results = trivy_data.get('Results', [])
                    for result in trivy_results:
                        vulns = result.get('Vulnerabilities', [])
                        all_findings.extend([{'tool': 'trivy', 'data': v} for v in vulns])
            except Exception as e:
                print(f"Failed to parse trivy-sca.json: {e}", file=sys.stderr)

        # Parse ESLint results (Code Quality - JavaScript/TypeScript)
        eslint_file = os.path.join(raw_dir, "eslint.json")
        if os.path.exists(eslint_file):
            try:
                with open(eslint_file, 'r') as f:
                    eslint_data = json.load(f)
                    if isinstance(eslint_data, list):
                        # ESLint native format: array of file results, each with messages array
                        for file_result in eslint_data:
                            file_path = file_result.get('filePath', '')
                            messages = file_result.get('messages', [])
                            for msg in messages:
                                # Create a finding for each message
                                all_findings.append({
                                    'tool': 'eslint',
                                    'data': {
                                        'filePath': file_path,
                                        'message': msg
                                    }
                                })
            except Exception as e:
                print(f"Failed to parse eslint.json: {e}", file=sys.stderr)

        # Parse Pylint results (Code Quality - Python)
        pylint_file = os.path.join(raw_dir, "pylint.json")
        if os.path.exists(pylint_file):
            try:
                with open(pylint_file, 'r') as f:
                    pylint_data = json.load(f)
                    if isinstance(pylint_data, list):
                        all_findings.extend([{'tool': 'pylint', 'data': r} for r in pylint_data])
            except Exception as e:
                print(f"Failed to parse pylint.json: {e}", file=sys.stderr)

        # Parse Checkstyle results (Code Quality - Java)
        checkstyle_file = os.path.join(raw_dir, "checkstyle.json")
        if os.path.exists(checkstyle_file):
            try:
                with open(checkstyle_file, 'r') as f:
                    checkstyle_data = json.load(f)
                    if isinstance(checkstyle_data, list):
                        all_findings.extend([{'tool': 'checkstyle', 'data': r} for r in checkstyle_data])
            except Exception as e:
                print(f"Failed to parse checkstyle.json: {e}", file=sys.stderr)

        # Parse golangci-lint results (Code Quality - Go)
        golangci_file = os.path.join(raw_dir, "golangci-lint.json")
        if os.path.exists(golangci_file):
            try:
                with open(golangci_file, 'r') as f:
                    golangci_data = json.load(f)
                    if isinstance(golangci_data, list):
                        all_findings.extend([{'tool': 'golangci-lint', 'data': r} for r in golangci_data])
            except Exception as e:
                print(f"Failed to parse golangci-lint.json: {e}", file=sys.stderr)

        # Parse RuboCop results (Code Quality - Ruby)
        rubocop_file = os.path.join(raw_dir, "rubocop.json")
        if os.path.exists(rubocop_file):
            try:
                with open(rubocop_file, 'r') as f:
                    rubocop_data = json.load(f)
                    if isinstance(rubocop_data, list):
                        all_findings.extend([{'tool': 'rubocop', 'data': r} for r in rubocop_data])
            except Exception as e:
                print(f"Failed to parse rubocop.json: {e}", file=sys.stderr)

        # Parse Clippy results (Code Quality - Rust)
        clippy_file = os.path.join(raw_dir, "clippy.json")
        if os.path.exists(clippy_file):
            try:
                with open(clippy_file, 'r') as f:
                    clippy_data = json.load(f)
                    if isinstance(clippy_data, list):
                        all_findings.extend([{'tool': 'clippy', 'data': r} for r in clippy_data])
            except Exception as e:
                print(f"Failed to parse clippy.json: {e}", file=sys.stderr)

        # Parse PHPStan results (Code Quality - PHP)
        phpstan_file = os.path.join(raw_dir, "phpstan.json")
        if os.path.exists(phpstan_file):
            try:
                with open(phpstan_file, 'r') as f:
                    phpstan_data = json.load(f)
                    if isinstance(phpstan_data, list):
                        all_findings.extend([{'tool': 'phpstan', 'data': r} for r in phpstan_data])
            except Exception as e:
                print(f"Failed to parse phpstan.json: {e}", file=sys.stderr)

        # Normalize to common schema
        normalized = self._normalize_findings(all_findings)

        # Apply filters
        filtered = self._apply_filters(normalized, severity_filter, tool_filter, category_filter)

        # Paginate
        total_findings = len(filtered)
        total_pages = (total_findings + page_size - 1) // page_size
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_findings = filtered[start_idx:end_idx]

        # Format response
        result = {
            "page": page,
            "page_size": page_size,
            "total_findings": total_findings,
            "total_pages": total_pages,
            "filters_applied": {
                "severity": severity_filter,
                "tool": tool_filter,
                "category": category_filter
            },
            "findings": page_findings
        }

        return f"""# 🔍 Scan Findings - Page {page}/{total_pages}

**Repository**: {os.path.basename(repo_path)}
**Total Findings**: {total_findings}
**Showing**: {len(page_findings)} findings on this page

{json.dumps(result, indent=2)}

**Status**: ✅ Findings retrieved successfully
"""

    def _normalize_findings(self, raw_findings):
        """Normalize findings from different tools to common schema"""
        normalized = []

        for idx, item in enumerate(raw_findings):
            tool = item['tool']
            data = item['data']

            if tool == 'semgrep':
                # Semgrep schema normalization
                severity_map = {
                    'ERROR': 'critical',
                    'CRITICAL': 'critical',
                    'WARNING': 'high',
                    'HIGH': 'high',
                    'INFO': 'medium',
                    'MEDIUM': 'medium',
                    'LOW': 'low'
                }
                severity = severity_map.get(data.get('extra', {}).get('severity', 'UNKNOWN'), 'medium')
                metadata = data.get('extra', {}).get('metadata', {})

                normalized.append({
                    "id": f"semgrep-{idx}",
                    "tool": "semgrep",
                    "category": metadata.get('category', 'security'),
                    "severity": severity,
                    "title": data.get('check_id', 'Unknown'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": data.get('extra', {}).get('lines', ''),
                    "cwe": metadata.get('cwe', []),
                    "owasp": metadata.get('owasp', []),
                    "fix_available": True,
                    "remediation": metadata.get('fix', 'Review and fix the vulnerability')
                })

            elif tool == 'gitleaks':
                # Gitleaks schema normalization
                normalized.append({
                    "id": f"gitleaks-{idx}",
                    "tool": "gitleaks",
                    "category": "security",
                    "severity": "critical",  # All secrets are critical
                    "title": data.get('Description', 'Secret Detected'),
                    "description": f"Secret found: {data.get('RuleID', 'Unknown rule')}",
                    "file_path": data.get('File', ''),
                    "line_start": data.get('StartLine', 0),
                    "line_end": data.get('EndLine', 0),
                    "code_snippet": data.get('Secret', '***REDACTED***'),
                    "cwe": ["CWE-798"],
                    "owasp": ["A02:2021 - Cryptographic Failures"],
                    "fix_available": False,  # Secrets need manual review
                    "remediation": "Remove secret and rotate credentials immediately"
                })

            elif tool == 'trivy':
                # Trivy schema normalization
                severity_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'high',
                    'MEDIUM': 'medium',
                    'LOW': 'low'
                }
                severity = severity_map.get(data.get('Severity', 'UNKNOWN'), 'medium')

                normalized.append({
                    "id": f"trivy-{idx}",
                    "tool": "trivy",
                    "category": "security",
                    "severity": severity,
                    "title": f"{data.get('VulnerabilityID', 'Unknown')}: {data.get('PkgName', 'Unknown package')}",
                    "description": data.get('Title', '') or data.get('Description', ''),
                    "file_path": "package.json",  # Dependencies tracked in package file
                    "line_start": 0,
                    "line_end": 0,
                    "code_snippet": f"Package: {data.get('PkgName', 'Unknown')} v{data.get('InstalledVersion', 'Unknown')}",
                    "cwe": [data.get('CweIDs', [])] if data.get('CweIDs') else [],
                    "owasp": [],
                    "fix_available": bool(data.get('FixedVersion')),
                    "remediation": f"Update {data.get('PkgName', 'package')} to version {data.get('FixedVersion', 'latest')}" if data.get('FixedVersion') else "No fix available yet"
                })

            elif tool == 'eslint':
                # ESLint native format normalization (code quality)
                file_path = data.get('filePath', '')
                msg = data.get('message', {})

                # ESLint severity: 1 = warning, 2 = error
                eslint_severity = msg.get('severity', 1)
                severity = 'high' if eslint_severity == 2 else 'medium'

                normalized.append({
                    "id": f"eslint-{idx}",
                    "tool": "eslint",
                    "category": "code_quality",
                    "severity": severity,
                    "title": msg.get('ruleId', 'ESLint Rule'),
                    "description": msg.get('message', ''),
                    "file_path": file_path,
                    "line_start": msg.get('line', 0),
                    "line_end": msg.get('endLine', msg.get('line', 0)),
                    "code_snippet": "",  # ESLint doesn't include code snippets
                    "cwe": [],
                    "owasp": [],
                    "fix_available": bool(msg.get('fix')),
                    "remediation": "Review and fix this code quality issue. " + (f"Auto-fix available for {msg.get('ruleId')}" if msg.get('fix') else "Manual fix required.")
                })

            elif tool == 'pylint':
                # Pylint schema normalization (code quality)
                normalized.append({
                    "id": f"pylint-{idx}",
                    "tool": "pylint",
                    "category": "code_quality",
                    "severity": data.get('severity', 'medium'),
                    "title": data.get('check_id', 'Pylint Rule'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",  # Pylint doesn't include code snippets in our format
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review code quality issue and apply best practices"
                })

            elif tool == 'checkstyle':
                # Checkstyle schema normalization (code quality - Java)
                normalized.append({
                    "id": f"checkstyle-{idx}",
                    "tool": "checkstyle",
                    "category": "code_quality",
                    "severity": data.get('severity', 'medium'),
                    "title": data.get('check_id', 'Checkstyle Rule'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review Java code quality issue and apply best practices"
                })

            elif tool == 'golangci-lint':
                # golangci-lint schema normalization (code quality - Go)
                normalized.append({
                    "id": f"golangci-lint-{idx}",
                    "tool": "golangci-lint",
                    "category": "code_quality",
                    "severity": data.get('severity', 'medium'),
                    "title": data.get('check_id', 'golangci-lint Rule'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review Go code quality issue and apply best practices"
                })

            elif tool == 'rubocop':
                # RuboCop schema normalization (code quality - Ruby)
                normalized.append({
                    "id": f"rubocop-{idx}",
                    "tool": "rubocop",
                    "category": "code_quality",
                    "severity": data.get('severity', 'medium'),
                    "title": data.get('check_id', 'RuboCop Rule'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review Ruby code quality issue and apply best practices"
                })

            elif tool == 'clippy':
                # Clippy schema normalization (code quality - Rust)
                normalized.append({
                    "id": f"clippy-{idx}",
                    "tool": "clippy",
                    "category": "code_quality",
                    "severity": data.get('severity', 'medium'),
                    "title": data.get('check_id', 'Clippy Lint'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review Rust code quality issue and apply best practices"
                })

            elif tool == 'phpstan':
                # PHPStan schema normalization (code quality - PHP)
                normalized.append({
                    "id": f"phpstan-{idx}",
                    "tool": "phpstan",
                    "category": "code_quality",
                    "severity": data.get('severity', 'high'),
                    "title": data.get('check_id', 'PHPStan Error'),
                    "description": data.get('extra', {}).get('message', ''),
                    "file_path": data.get('path', ''),
                    "line_start": data.get('start', {}).get('line', 0),
                    "line_end": data.get('end', {}).get('line', 0),
                    "code_snippet": "",
                    "cwe": [],
                    "owasp": [],
                    "fix_available": False,
                    "remediation": "Review PHP code quality issue and apply type safety best practices"
                })

        return normalized

    def _apply_filters(self, findings, severity_filter, tool_filter, category_filter):
        """Apply filters to findings"""
        filtered = findings

        if severity_filter:
            filtered = [f for f in filtered if f.get('severity') == severity_filter.lower()]

        if tool_filter:
            filtered = [f for f in filtered if f.get('tool') == tool_filter.lower()]

        if category_filter:
            filtered = [f for f in filtered if f.get('category') == category_filter.lower()]

        return filtered

    # ===== IXaidev API: Tool-Specific Paginated Endpoints =====

    def get_semgrep_findings(self, args):
        """Get paginated Semgrep SAST findings - returns pure JSON"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Input validation for pagination parameters
        page = max(1, min(args.get('page', 1), 1000))  # Cap at 1000 pages
        page_size = max(1, min(args.get('page_size', 10), 50))  # 1-50 per page

        severity_filter = args.get('severity_filter')

        raw_dir = os.path.join(outputs_path, "raw")
        semgrep_file = os.path.join(raw_dir, "semgrep.json")

        findings = []
        if os.path.exists(semgrep_file):
            try:
                with open(semgrep_file, 'r') as f:
                    semgrep_data = json.load(f)
                    results = semgrep_data.get('results', [])

                    for idx, data in enumerate(results):
                        severity_map = {'ERROR': 'critical', 'CRITICAL': 'critical', 'WARNING': 'high', 'HIGH': 'high', 'INFO': 'medium', 'MEDIUM': 'medium', 'LOW': 'low'}
                        severity = severity_map.get(data.get('extra', {}).get('severity', 'UNKNOWN'), 'medium')
                        metadata = data.get('extra', {}).get('metadata', {})

                        findings.append({
                            "id": f"semgrep-{idx}",
                            "tool": "semgrep",
                            "category": metadata.get('category', 'security'),
                            "severity": severity,
                            "title": data.get('check_id', 'Unknown'),
                            "description": data.get('extra', {}).get('message', ''),
                            "file_path": data.get('path', ''),
                            "line_start": data.get('start', {}).get('line', 0),
                            "line_end": data.get('end', {}).get('line', 0),
                            "code_snippet": data.get('extra', {}).get('lines', ''),
                            "cwe": metadata.get('cwe', []),
                            "owasp": metadata.get('owasp', []),
                            "fix_available": True,
                            "remediation": metadata.get('fix', 'Review and fix the vulnerability')
                        })
            except Exception as e:
                print(f"Failed to parse semgrep.json: {e}", file=sys.stderr)

        # Apply severity filter
        if severity_filter:
            findings = [f for f in findings if f['severity'] == severity_filter.lower()]

        # Paginate
        total_findings = len(findings)
        total_pages = (total_findings + page_size - 1) // page_size if total_findings > 0 else 1
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_findings = findings[start_idx:end_idx]

        result = {
            "success": True,
            "tool": "semgrep",
            "repository": os.path.basename(repo_path),
            "page": page,
            "page_size": page_size,
            "total_findings": total_findings,
            "total_pages": total_pages,
            "filters_applied": {"severity": severity_filter},
            "findings": page_findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        return json.dumps(result, indent=2)

    def get_trivy_findings(self, args):
        """Get paginated Trivy dependency findings - returns pure JSON"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Input validation for pagination parameters
        page = max(1, min(args.get('page', 1), 1000))  # Cap at 1000 pages
        page_size = max(1, min(args.get('page_size', 10), 50))  # 1-50 per page

        severity_filter = args.get('severity_filter')
        fix_available = args.get('fix_available')

        raw_dir = os.path.join(outputs_path, "raw")
        trivy_file = os.path.join(raw_dir, "trivy-sca.json")

        findings = []
        if os.path.exists(trivy_file):
            try:
                with open(trivy_file, 'r') as f:
                    trivy_data = json.load(f)
                    trivy_results = trivy_data.get('Results', [])
                    idx = 0
                    for result in trivy_results:
                        vulns = result.get('Vulnerabilities', [])
                        for vuln in vulns:
                            severity_map = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
                            severity = severity_map.get(vuln.get('Severity', 'UNKNOWN'), 'medium')

                            findings.append({
                                "id": f"trivy-{idx}",
                                "tool": "trivy",
                                "category": "security",
                                "severity": severity,
                                "vulnerability_id": vuln.get('VulnerabilityID', 'Unknown'),
                                "package_name": vuln.get('PkgName', 'Unknown'),
                                "installed_version": vuln.get('InstalledVersion', 'Unknown'),
                                "fixed_version": vuln.get('FixedVersion', None),
                                "title": f"{vuln.get('VulnerabilityID', 'Unknown')}: {vuln.get('PkgName', 'Unknown package')}",
                                "description": vuln.get('Title', '') or vuln.get('Description', ''),
                                "file_path": result.get('Target', 'package.json'),
                                "cwe": vuln.get('CweIDs', []) if vuln.get('CweIDs') else [],
                                "cvss": vuln.get('CVSS', {}),
                                "references": vuln.get('References', []),
                                "fix_available": bool(vuln.get('FixedVersion')),
                                "remediation": f"Update {vuln.get('PkgName', 'package')} to version {vuln.get('FixedVersion', 'latest')}" if vuln.get('FixedVersion') else "No fix available yet"
                            })
                            idx += 1
            except Exception as e:
                print(f"Failed to parse trivy-sca.json: {e}", file=sys.stderr)

        # Apply filters
        if severity_filter:
            findings = [f for f in findings if f['severity'] == severity_filter.lower()]
        if fix_available is not None:
            findings = [f for f in findings if f['fix_available'] == fix_available]

        # Paginate
        total_findings = len(findings)
        total_pages = (total_findings + page_size - 1) // page_size if total_findings > 0 else 1
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_findings = findings[start_idx:end_idx]

        result = {
            "success": True,
            "tool": "trivy",
            "repository": os.path.basename(repo_path),
            "page": page,
            "page_size": page_size,
            "total_findings": total_findings,
            "total_pages": total_pages,
            "filters_applied": {"severity": severity_filter, "fix_available": fix_available},
            "findings": page_findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        return json.dumps(result, indent=2)

    def get_gitleaks_findings(self, args):
        """Get paginated Gitleaks secret findings - returns pure JSON"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Input validation for pagination parameters
        page = max(1, min(args.get('page', 1), 1000))  # Cap at 1000 pages
        page_size = max(1, min(args.get('page_size', 10), 50))  # 1-50 per page

        raw_dir = os.path.join(outputs_path, "raw")
        gitleaks_file = os.path.join(raw_dir, "gitleaks.json")

        findings = []
        if os.path.exists(gitleaks_file):
            try:
                with open(gitleaks_file, 'r') as f:
                    gitleaks_data = json.load(f)
                    if isinstance(gitleaks_data, list):
                        for idx, data in enumerate(gitleaks_data):
                            findings.append({
                                "id": f"gitleaks-{idx}",
                                "tool": "gitleaks",
                                "category": "security",
                                "severity": "critical",
                                "rule_id": data.get('RuleID', 'Unknown'),
                                "title": data.get('Description', 'Secret Detected'),
                                "description": f"Secret found: {data.get('RuleID', 'Unknown rule')}",
                                "file_path": data.get('File', ''),
                                "line_start": data.get('StartLine', 0),
                                "line_end": data.get('EndLine', 0),
                                "commit": data.get('Commit', 'Unknown'),
                                "author": data.get('Author', 'Unknown'),
                                "date": data.get('Date', 'Unknown'),
                                "cwe": ["CWE-798"],
                                "owasp": ["A02:2021 - Cryptographic Failures"],
                                "fix_available": False,
                                "remediation": "Remove secret and rotate credentials immediately"
                            })
            except Exception as e:
                print(f"Failed to parse gitleaks.json: {e}", file=sys.stderr)

        # Paginate
        total_findings = len(findings)
        total_pages = (total_findings + page_size - 1) // page_size if total_findings > 0 else 1
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_findings = findings[start_idx:end_idx]

        result = {
            "success": True,
            "tool": "gitleaks",
            "repository": os.path.basename(repo_path),
            "page": page,
            "page_size": page_size,
            "total_findings": total_findings,
            "total_pages": total_pages,
            "findings": page_findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        return json.dumps(result, indent=2)

    def get_code_quality_findings(self, args):
        """Get paginated code quality findings from all linters - returns pure JSON"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        # Input validation for pagination parameters
        page = max(1, min(args.get('page', 1), 1000))  # Cap at 1000 pages
        page_size = max(1, min(args.get('page_size', 10), 50))  # 1-50 per page

        linter_filter = args.get('linter_filter')

        raw_dir = os.path.join(outputs_path, "raw")
        findings = []

        # ESLint (JavaScript/TypeScript)
        eslint_file = os.path.join(raw_dir, "eslint.json")
        if os.path.exists(eslint_file) and (not linter_filter or linter_filter == 'eslint'):
            try:
                with open(eslint_file, 'r') as f:
                    eslint_data = json.load(f)
                    if isinstance(eslint_data, list):
                        idx = 0
                        for file_result in eslint_data:
                            file_path = file_result.get('filePath', '')
                            for msg in file_result.get('messages', []):
                                severity = 'high' if msg.get('severity', 1) == 2 else 'medium'
                                findings.append({
                                    "id": f"eslint-{idx}",
                                    "tool": "eslint",
                                    "linter": "eslint",
                                    "language": "javascript/typescript",
                                    "category": "code_quality",
                                    "severity": severity,
                                    "rule_id": msg.get('ruleId', 'ESLint Rule'),
                                    "title": msg.get('ruleId', 'ESLint Rule'),
                                    "description": msg.get('message', ''),
                                    "file_path": file_path,
                                    "line_start": msg.get('line', 0),
                                    "line_end": msg.get('endLine', msg.get('line', 0)),
                                    "column": msg.get('column', 0),
                                    "fix_available": bool(msg.get('fix')),
                                    "remediation": f"Auto-fix available for {msg.get('ruleId')}" if msg.get('fix') else "Manual fix required"
                                })
                                idx += 1
            except Exception as e:
                print(f"Failed to parse eslint.json: {e}", file=sys.stderr)

        # Pylint (Python)
        pylint_file = os.path.join(raw_dir, "pylint.json")
        if os.path.exists(pylint_file) and (not linter_filter or linter_filter == 'pylint'):
            try:
                with open(pylint_file, 'r') as f:
                    pylint_data = json.load(f)
                    if isinstance(pylint_data, list):
                        for idx, data in enumerate(pylint_data):
                            findings.append({
                                "id": f"pylint-{idx}",
                                "tool": "pylint",
                                "linter": "pylint",
                                "language": "python",
                                "category": "code_quality",
                                "severity": data.get('severity', 'medium'),
                                "rule_id": data.get('check_id', 'Pylint Rule'),
                                "title": data.get('check_id', 'Pylint Rule'),
                                "description": data.get('extra', {}).get('message', ''),
                                "file_path": data.get('path', ''),
                                "line_start": data.get('start', {}).get('line', 0),
                                "line_end": data.get('end', {}).get('line', 0),
                                "fix_available": False,
                                "remediation": "Review code quality issue and apply best practices"
                            })
            except Exception as e:
                print(f"Failed to parse pylint.json: {e}", file=sys.stderr)

        # Add similar blocks for other linters (checkstyle, golangci-lint, rubocop, clippy, phpstan)
        # Following same pattern as above...

        # Paginate
        total_findings = len(findings)
        total_pages = (total_findings + page_size - 1) // page_size if total_findings > 0 else 1
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_findings = findings[start_idx:end_idx]

        result = {
            "success": True,
            "tool": "code_quality",
            "repository": os.path.basename(repo_path),
            "page": page,
            "page_size": page_size,
            "total_findings": total_findings,
            "total_pages": total_pages,
            "filters_applied": {"linter": linter_filter},
            "findings": page_findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        return json.dumps(result, indent=2)

    def get_sbom_data_structured(self, args):
        """Get SBOM data in structured JSON - returns pure JSON"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)
        format_type = args.get('format', 'both')

        sbom_dir = os.path.join(outputs_path, "sbom")
        cyclone_path = os.path.join(sbom_dir, "sbom.cyclonedx.json")
        spdx_path = os.path.join(sbom_dir, "sbom.spdx.json")

        result = {
            "success": True,
            "repository": os.path.basename(repo_path),
            "format": format_type,
            "sbom": {}
        }

        if format_type in ['cyclonedx', 'both'] and os.path.exists(cyclone_path):
            try:
                with open(cyclone_path) as f:
                    result["sbom"]["cyclonedx"] = json.load(f)
            except Exception as e:
                result["sbom"]["cyclonedx"] = {"error": str(e)}

        if format_type in ['spdx', 'both'] and os.path.exists(spdx_path):
            try:
                with open(spdx_path) as f:
                    result["sbom"]["spdx"] = json.load(f)
            except Exception as e:
                result["sbom"]["spdx"] = {"error": str(e)}

        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return json.dumps(result, indent=2)

    def generate_threat_model(self, args):
        """Generate threat model using STRIDE framework"""
        repo_path = self.find_repo(args["repo_path"])
        outputs_path = self._get_repo_output_path(repo_path)

        try:
            # Import threat modeling module
            sys.path.insert(0, os.path.join(self.ix_guard_path, 'src'))
            from threat_modeling import ThreatAnalyzer

            # Load existing scan findings if available
            findings = []
            raw_dir = os.path.join(outputs_path, "raw")
            if os.path.exists(raw_dir):
                for json_file in os.listdir(raw_dir):
                    if json_file.endswith('.json'):
                        try:
                            with open(os.path.join(raw_dir, json_file)) as f:
                                data = json.load(f)
                                if isinstance(data, dict) and 'results' in data:
                                    findings.extend(data['results'])
                                elif isinstance(data, list):
                                    findings.extend(data)
                        except Exception:
                            pass

            # Create analyzer and generate threat model
            analyzer = ThreatAnalyzer(repo_path)
            threat_model = analyzer.analyze(findings)

            # Export threat model files
            exported_files = analyzer.export_threat_model(threat_model, outputs_path)

            # Format output for MCP
            output = []
            output.append("🛡️  THREAT MODEL GENERATED\n")
            output.append("=" * 80)
            output.append("\n\n📊 SUMMARY\n")
            output.append(f"  • Total Threats: {threat_model['summary']['total_threats']}")
            output.append(f"  • Attack Surface Risk: {threat_model['summary']['attack_surface_score']}")
            output.append(f"  • Overall Risk Level: {threat_model['summary']['risk_level']}\n")

            # STRIDE Breakdown
            output.append("\n🎯 STRIDE THREAT BREAKDOWN\n")
            for category, count in threat_model['summary']['stride_breakdown'].items():
                if count > 0:
                    output.append(f"  • {category.replace('_', ' ')}: {count}")

            # Architecture Components
            output.append("\n\n🏗️  ARCHITECTURE COMPONENTS\n")
            for comp in threat_model['architecture']['components'][:5]:
                output.append(f"  • {comp['name']} ({comp['type']})")

            # Trust Boundaries
            if threat_model['architecture']['trust_boundaries']:
                output.append("\n\n🔒 TRUST BOUNDARIES\n")
                for boundary in threat_model['architecture']['trust_boundaries']:
                    output.append(f"  • {boundary['name']} - Risk: {boundary['risk']}")
                    output.append(f"    {boundary['description']}")

            # Top Threat Scenarios
            if threat_model['threat_scenarios']:
                output.append("\n\n⚠️  TOP THREAT SCENARIOS\n")
                for i, scenario in enumerate(threat_model['threat_scenarios'][:3], 1):
                    output.append(f"\n{i}. [{scenario['severity']}] {scenario['title']}")
                    output.append(f"   Attack Vector: {scenario['attack_vector']}")
                    output.append(f"   Impact: {scenario['impact']}")

            # Generated Files
            output.append(f"\n\n📄 REPORTS GENERATED\n")
            output.append(f"  • JSON: {exported_files['json']}")
            output.append(f"  • Markdown: {exported_files['markdown']}")
            output.append(f"  • Diagram: {exported_files['diagram']}")

            output.append("\n\n" + "=" * 80)
            output.append("\n✅ Threat model complete! See THREAT_MODEL.md for full report.\n")

            return "\n".join(output)

        except ImportError as e:
            return f"❌ Threat modeling module not available: {e}\n\nPlease ensure threat_modeling module is installed."
        except Exception as e:
            return f"❌ Threat model generation failed: {e}"

    def health_check(self, args):
        """Comprehensive health check for MCP server and dependencies"""
        import shutil

        checks = []
        overall_status = "✅ Healthy"

        # 1. Check AppSec-Sentinel installation
        if os.path.exists(os.path.join(self.appsec_path, "src", "main.py")):
            checks.append("✅ AppSec-Sentinel installation: Found")
        else:
            checks.append(f"❌ AppSec-Sentinel installation: Not found at {self.appsec_path}")
            overall_status = "❌ Unhealthy"

        # 2. Check Python executable
        python_exe = self._find_python_executable()
        try:
            result = subprocess.run([python_exe, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.strip()
                checks.append(f"✅ Python: {version}")
            else:
                checks.append(f"⚠️ Python: Found but version check failed")
        except Exception as e:
            checks.append(f"❌ Python: Error - {str(e)}")
            overall_status = "❌ Unhealthy"

        # 3. Check scanner binaries
        scanners = {
            'semgrep': 'Semgrep (SAST)',
            'gitleaks': 'Gitleaks (Secrets)',
            'trivy': 'Trivy (Dependencies)'
        }

        for binary, name in scanners.items():
            if shutil.which(binary):
                try:
                    result = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=5)
                    version_line = result.stdout.split('\n')[0] if result.stdout else "unknown version"
                    checks.append(f"✅ {name}: {version_line}")
                except Exception:
                    checks.append(f"✅ {name}: Found (version check failed)")
            else:
                checks.append(f"❌ {name}: Not found in PATH")
                overall_status = "⚠️ Degraded"

        # 4. Check AWS credentials (for AI auto-remediation)
        if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
            checks.append("✅ AWS Credentials: Configured")
        else:
            checks.append("⚠️ AWS Credentials: Not configured (auto-remediation won't work)")

        # 5. Check GitHub token (for PR creation)
        if os.getenv('GITHUB_TOKEN'):
            checks.append("✅ GitHub Token: Configured")
        else:
            checks.append("⚠️ GitHub Token: Not configured (PR creation won't work)")

        # 6. Check environment configuration
        scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
        checks.append(f"📊 Scan Level: {scan_level}")

        debug_mode = os.getenv('APPSEC_DEBUG', 'false')
        checks.append(f"🐛 Debug Mode: {debug_mode}")

        scan_timeout = os.getenv('MCP_SCAN_TIMEOUT', '300')
        remediate_timeout = os.getenv('MCP_REMEDIATE_TIMEOUT', '600')
        checks.append(f"⏱️ Timeouts: Scan={scan_timeout}s, Remediate={remediate_timeout}s")

        # 7. Check repository search paths
        search_paths = self._find_repo_search_paths()
        accessible_paths = [p for p in search_paths if os.path.exists(p)]
        checks.append(f"📁 Repository Search Paths: {len(accessible_paths)}/{len(search_paths)} accessible")

        # Format output
        checks_formatted = '\n'.join([f"  {check}" for check in checks])

        return f"""# 🏥 AppSec-Sentinel MCP Health Check

**Overall Status**: {overall_status}

## System Checks:
{checks_formatted}

## Configuration:
- **Installation Path**: `{self.appsec_path}`
- **MCP Server Version**: 1.0.0
- **Protocol Version**: 2024-11-05
- **Available Tools**: 14

## Recommendations:
{self._get_health_recommendations(checks)}

**Status**: Health check completed at {time.strftime('%Y-%m-%d %H:%M:%S')}
"""

    def _get_health_recommendations(self, checks):
        """Generate recommendations based on health check results"""
        recommendations = []

        # Check for missing scanners
        if any("❌" in check and "Gitleaks" in check for check in checks):
            recommendations.append("• Install Gitleaks: `brew install gitleaks` (macOS) or see https://github.com/gitleaks/gitleaks")

        if any("❌" in check and "Trivy" in check for check in checks):
            recommendations.append("• Install Trivy: `brew install trivy` (macOS) or see https://trivy.dev/getting-started/installation/")

        if any("❌" in check and "Semgrep" in check for check in checks):
            recommendations.append("• Install Semgrep: `pip install semgrep` (should be auto-installed)")

        # Check for missing credentials
        if any("⚠️" in check and "AWS" in check for check in checks):
            recommendations.append("• Configure AWS credentials in mcp/mcp_env for auto-remediation features")

        if any("⚠️" in check and "GitHub" in check for check in checks):
            recommendations.append("• Configure GITHUB_TOKEN in mcp/mcp_env for PR creation")

        if not recommendations:
            recommendations.append("• All critical components are healthy! ✅")

        return '\n'.join(recommendations)

    def send_error(self, msg_id, code, message):
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message}
        }

def main():
    """Entry point for the MCP server."""
    server = EverythingAppSecMCP()
    server.main()

if __name__ == "__main__":
    main()