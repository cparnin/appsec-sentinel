"""
Threat Modeling Analyzer

Generates threat models using STRIDE framework, architecture mapping,
and attack surface analysis.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict


class ThreatAnalyzer:
    """Automated threat modeling using STRIDE and architecture analysis"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.threats = []
        self.components = []
        self.entry_points = []
        self.data_stores = []
        self.trust_boundaries = []

    def analyze(self, findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate comprehensive threat model

        Args:
            findings: Security scan findings from AppSec-Sentinel

        Returns:
            Dict containing threat model with STRIDE analysis, architecture, and attack surface
        """
        # Discover architecture components
        self._discover_architecture()

        # Map attack surface
        attack_surface = self._map_attack_surface()

        # Apply STRIDE framework
        stride_threats = self._apply_stride(findings or [])

        # Identify trust boundaries
        trust_boundaries = self._identify_trust_boundaries()

        # Generate threat scenarios
        threat_scenarios = self._generate_threat_scenarios(findings or [])

        return {
            'architecture': {
                'components': self.components,
                'entry_points': self.entry_points,
                'data_stores': self.data_stores,
                'trust_boundaries': trust_boundaries
            },
            'attack_surface': attack_surface,
            'stride_analysis': stride_threats,
            'threat_scenarios': threat_scenarios,
            'summary': self._generate_summary(stride_threats, attack_surface)
        }

    def _discover_architecture(self):
        """Discover architectural components from codebase"""

        # Framework detection patterns
        frameworks = {
            'express': ['express()', 'app.get', 'app.post', 'router.'],
            'flask': ['@app.route', 'Flask(__name__)', 'Blueprint'],
            'django': ['django.', 'models.Model', 'views.py'],
            'spring': ['@RestController', '@Controller', '@Service', '@Repository'],
            'rails': ['ActionController', 'ApplicationController', 'ActiveRecord'],
            'laravel': ['Route::', 'Illuminate\\', 'Controller'],
            'fastapi': ['FastAPI()', '@app.get', '@app.post']
        }

        detected_frameworks = []

        # Scan for frameworks and components
        for ext in ['.js', '.ts', '.py', '.java', '.rb', '.php', '.go', '.rs']:
            for file_path in self.repo_path.rglob(f'*{ext}'):
                if self._should_skip_path(file_path):
                    continue

                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')

                    # Detect frameworks
                    for fw, patterns in frameworks.items():
                        if any(p in content for p in patterns):
                            if fw not in detected_frameworks:
                                detected_frameworks.append(fw)
                                self.components.append({
                                    'name': fw.title(),
                                    'type': 'web_framework',
                                    'file': str(file_path.relative_to(self.repo_path))
                                })

                    # Detect entry points (routes, controllers, APIs)
                    if any(p in content for p in ['@app.', 'app.get', 'app.post', 'Route::', '@RestController', '@RequestMapping']):
                        self.entry_points.append({
                            'file': str(file_path.relative_to(self.repo_path)),
                            'type': 'http_endpoint'
                        })

                    # Detect data stores
                    if any(p in content for p in ['mongoose.', 'Sequelize', 'models.Model', 'JpaRepository', 'ActiveRecord', 'PDO', 'sql.DB']):
                        if str(file_path.relative_to(self.repo_path)) not in [d['file'] for d in self.data_stores]:
                            self.data_stores.append({
                                'file': str(file_path.relative_to(self.repo_path)),
                                'type': 'database'
                            })

                except Exception:
                    continue

        # Add generic components if none detected
        if not self.components:
            self.components.append({
                'name': 'Application',
                'type': 'generic',
                'file': 'multiple'
            })

    def _map_attack_surface(self) -> Dict[str, Any]:
        """Map external-facing attack surface"""

        attack_surface = {
            'http_endpoints': len(self.entry_points),
            'entry_points': self.entry_points[:10],  # Top 10
            'data_stores': len(self.data_stores),
            'external_dependencies': self._count_dependencies(),
            'user_input_handlers': self._identify_input_handlers()
        }

        return attack_surface

    def _apply_stride(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Apply STRIDE threat framework"""

        stride = {
            'Spoofing': [],
            'Tampering': [],
            'Repudiation': [],
            'Information_Disclosure': [],
            'Denial_of_Service': [],
            'Elevation_of_Privilege': []
        }

        # Map findings to STRIDE categories
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            title = finding.get('check_id', finding.get('title', '')).lower()

            # Spoofing - Authentication threats
            if any(k in title for k in ['auth', 'jwt', 'session', 'login', 'credential']):
                stride['Spoofing'].append({
                    'threat': f"Authentication bypass in {finding.get('path', 'unknown')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

            # Tampering - Data integrity
            if any(k in title for k in ['sql', 'injection', 'xss', 'csrf', 'path-traversal']):
                stride['Tampering'].append({
                    'threat': f"Data tampering via {finding.get('check_id', 'injection')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

            # Repudiation - Logging/audit
            if any(k in title for k in ['log', 'audit', 'tracking']):
                stride['Repudiation'].append({
                    'threat': f"Missing audit trail in {finding.get('path', 'unknown')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

            # Information Disclosure - Data leakage
            if any(k in title for k in ['secret', 'password', 'token', 'key', 'sensitive', 'hardcoded', 'disclosure']):
                stride['Information_Disclosure'].append({
                    'threat': f"Information leakage: {finding.get('check_id', 'sensitive data')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

            # Denial of Service
            if any(k in title for k in ['dos', 'regex', 'resource', 'rate-limit']):
                stride['Denial_of_Service'].append({
                    'threat': f"Resource exhaustion via {finding.get('check_id', 'uncontrolled resource')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

            # Elevation of Privilege
            if any(k in title for k in ['command', 'exec', 'eval', 'deserialization', 'xxe', 'rce', 'privilege']):
                stride['Elevation_of_Privilege'].append({
                    'threat': f"Privilege escalation via {finding.get('check_id', 'code execution')}",
                    'severity': severity,
                    'finding': finding.get('check_id', title)
                })

        return stride

    def _identify_trust_boundaries(self) -> List[Dict]:
        """Identify trust boundaries in the architecture"""

        boundaries = []

        # Web application trust boundaries
        if self.entry_points:
            boundaries.append({
                'name': 'External → Application',
                'description': 'User requests crossing from untrusted internet to application',
                'risk': 'HIGH',
                'controls_needed': ['Input validation', 'Authentication', 'Rate limiting']
            })

        if self.data_stores:
            boundaries.append({
                'name': 'Application → Database',
                'description': 'Application queries crossing to data layer',
                'risk': 'MEDIUM',
                'controls_needed': ['Parameterized queries', 'Least privilege', 'Connection encryption']
            })

        # Check for external dependencies
        if self._count_dependencies() > 0:
            boundaries.append({
                'name': 'Application → Third-party Services',
                'description': 'Outbound connections to external APIs and services',
                'risk': 'MEDIUM',
                'controls_needed': ['Certificate validation', 'API authentication', 'Input sanitization']
            })

        return boundaries

    def _generate_threat_scenarios(self, findings: List[Dict]) -> List[Dict]:
        """Generate concrete threat scenarios based on findings"""

        scenarios = []

        # Group findings by severity
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        high_findings = [f for f in findings if f.get('severity') == 'HIGH']

        # Generate scenarios for critical/high findings
        for finding in (critical_findings + high_findings)[:10]:  # Top 10
            scenario = {
                'title': finding.get('check_id', finding.get('title', 'Security Issue')),
                'severity': finding.get('severity', 'MEDIUM'),
                'attack_vector': self._describe_attack_vector(finding),
                'impact': self._describe_impact(finding),
                'mitigation': finding.get('extra', {}).get('message', 'Apply security patch')
            }
            scenarios.append(scenario)

        return scenarios

    def _describe_attack_vector(self, finding: Dict) -> str:
        """Generate attack vector description"""
        check_id = finding.get('check_id', '').lower()

        if 'sql' in check_id or 'injection' in check_id:
            return "Attacker supplies malicious input that gets executed as code"
        elif 'xss' in check_id:
            return "Attacker injects malicious scripts into web pages viewed by users"
        elif 'auth' in check_id:
            return "Attacker bypasses authentication to gain unauthorized access"
        elif 'secret' in check_id or 'password' in check_id:
            return "Attacker extracts hardcoded credentials from source code or binaries"
        elif 'command' in check_id or 'exec' in check_id:
            return "Attacker executes arbitrary commands on the server"
        elif 'path' in check_id:
            return "Attacker accesses files outside intended directory structure"
        else:
            return "Attacker exploits vulnerability to compromise system"

    def _describe_impact(self, finding: Dict) -> str:
        """Generate impact description"""
        severity = finding.get('severity', 'MEDIUM')

        if severity == 'CRITICAL':
            return "Complete system compromise, data breach, or service disruption"
        elif severity == 'HIGH':
            return "Significant data exposure, unauthorized access, or system instability"
        elif severity == 'MEDIUM':
            return "Limited information disclosure or degraded functionality"
        else:
            return "Minor security weakness with limited exploitability"

    def _generate_summary(self, stride: Dict, attack_surface: Dict) -> Dict:
        """Generate threat model summary"""

        total_threats = sum(len(v) for v in stride.values())

        return {
            'total_threats': total_threats,
            'stride_breakdown': {k: len(v) for k, v in stride.items()},
            'attack_surface_score': self._calculate_attack_surface_score(attack_surface),
            'risk_level': self._calculate_risk_level(total_threats, attack_surface)
        }

    def _calculate_attack_surface_score(self, attack_surface: Dict) -> str:
        """Calculate attack surface risk score"""
        score = 0
        score += min(attack_surface.get('http_endpoints', 0) * 2, 50)
        score += min(attack_surface.get('data_stores', 0) * 10, 30)
        score += min(attack_surface.get('external_dependencies', 0) * 1, 20)

        if score > 70:
            return "HIGH"
        elif score > 40:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_risk_level(self, threat_count: int, attack_surface: Dict) -> str:
        """Calculate overall risk level"""
        if threat_count > 20 or attack_surface.get('http_endpoints', 0) > 20:
            return "HIGH"
        elif threat_count > 10 or attack_surface.get('http_endpoints', 0) > 10:
            return "MEDIUM"
        else:
            return "LOW"

    def _identify_input_handlers(self) -> List[str]:
        """Identify user input handlers"""
        handlers = set()

        for file_path in self.repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.js', '.ts', '.py', '.java', '.rb', '.php']:
                if self._should_skip_path(file_path):
                    continue
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')

                    # Detect input handlers
                    input_patterns = ['req.body', 'request.form', 'request.POST', 'request.GET',
                                     '@RequestBody', 'params[:' , '$_POST', '$_GET', 'ctx.request.body']

                    if any(p in content for p in input_patterns):
                        handlers.add(str(file_path.relative_to(self.repo_path)))

                except Exception:
                    continue

        return list(handlers)[:10]  # Top 10

    def _count_dependencies(self) -> int:
        """Count external dependencies"""
        count = 0

        # package.json
        pkg_json = self.repo_path / 'package.json'
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                count += len(data.get('dependencies', {}))
            except Exception:
                pass

        # requirements.txt
        req_txt = self.repo_path / 'requirements.txt'
        if req_txt.exists():
            try:
                count += len([l for l in req_txt.read_text().splitlines() if l.strip() and not l.startswith('#')])
            except Exception:
                pass

        # go.mod
        go_mod = self.repo_path / 'go.mod'
        if go_mod.exists():
            try:
                count += len([l for l in go_mod.read_text().splitlines() if 'require' in l])
            except Exception:
                pass

        return count

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped"""
        skip_dirs = {'node_modules', '.git', 'vendor', 'venv', '.venv', 'dist', 'build', '__pycache__'}
        return any(skip_dir in path.parts for skip_dir in skip_dirs)

    def generate_mermaid_diagram(self, threat_model: Dict) -> str:
        """Generate Mermaid architecture diagram"""

        lines = [
            "```mermaid",
            "graph TB",
            "    User[External User]",
        ]

        # Add components
        components = threat_model['architecture']['components']
        for i, comp in enumerate(components):
            comp_id = f"C{i}"
            lines.append(f"    {comp_id}[{comp['name']}]")

        # Add data stores
        for i, ds in enumerate(threat_model['architecture']['data_stores']):
            ds_id = f"DB{i}"
            lines.append(f"    {ds_id}[(Database)]")

        # Add connections
        if components:
            lines.append(f"    User -->|HTTP Request| C0")

        if threat_model['architecture']['data_stores']:
            lines.append(f"    C0 -->|Query| DB0")

        # Add trust boundaries
        lines.append("")
        lines.append("    subgraph TB1[Trust Boundary: Internet]")
        lines.append("        User")
        lines.append("    end")
        lines.append("")
        lines.append("    subgraph TB2[Trust Boundary: Application]")
        if components:
            lines.append("        C0")
        lines.append("    end")
        lines.append("")
        if threat_model['architecture']['data_stores']:
            lines.append("    subgraph TB3[Trust Boundary: Data Layer]")
            lines.append("        DB0")
            lines.append("    end")

        lines.append("```")

        return "\n".join(lines)

    def export_threat_model(self, threat_model: Dict, output_dir: str):
        """Export threat model to files"""

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Export JSON
        json_file = output_path / 'threat_model.json'
        with open(json_file, 'w') as f:
            json.dump(threat_model, f, indent=2)

        # Export Markdown
        md_file = output_path / 'THREAT_MODEL.md'
        md_content = self._generate_markdown_report(threat_model)
        md_file.write_text(md_content)

        # Export Mermaid diagram
        mermaid_file = output_path / 'architecture.mermaid'
        mermaid_content = self.generate_mermaid_diagram(threat_model)
        mermaid_file.write_text(mermaid_content)

        return {
            'json': str(json_file),
            'markdown': str(md_file),
            'diagram': str(mermaid_file)
        }

    def _generate_markdown_report(self, threat_model: Dict) -> str:
        """Generate markdown threat model report"""

        lines = [
            "# Threat Model Report",
            "",
            "## Executive Summary",
            "",
            f"- **Total Threats Identified:** {threat_model['summary']['total_threats']}",
            f"- **Attack Surface Risk:** {threat_model['summary']['attack_surface_score']}",
            f"- **Overall Risk Level:** {threat_model['summary']['risk_level']}",
            "",
            "## Architecture Overview",
            "",
            "### Components",
            ""
        ]

        for comp in threat_model['architecture']['components']:
            lines.append(f"- **{comp['name']}** ({comp['type']})")

        lines.extend([
            "",
            "### Entry Points",
            "",
            f"- **HTTP Endpoints:** {threat_model['attack_surface']['http_endpoints']}",
            f"- **Data Stores:** {threat_model['attack_surface']['data_stores']}",
            f"- **External Dependencies:** {threat_model['attack_surface']['external_dependencies']}",
            "",
            "## STRIDE Threat Analysis",
            ""
        ])

        for category, threats in threat_model['stride_analysis'].items():
            lines.append(f"### {category.replace('_', ' ')}")
            lines.append("")
            if threats:
                for threat in threats:
                    lines.append(f"- **[{threat['severity']}]** {threat['threat']}")
            else:
                lines.append("- No threats identified")
            lines.append("")

        lines.extend([
            "## Trust Boundaries",
            ""
        ])

        for boundary in threat_model['architecture']['trust_boundaries']:
            lines.extend([
                f"### {boundary['name']}",
                "",
                f"**Risk:** {boundary['risk']}",
                "",
                f"{boundary['description']}",
                "",
                "**Required Controls:**",
                ""
            ])
            for control in boundary['controls_needed']:
                lines.append(f"- {control}")
            lines.append("")

        lines.extend([
            "## Top Threat Scenarios",
            ""
        ])

        for i, scenario in enumerate(threat_model['threat_scenarios'][:5], 1):
            lines.extend([
                f"### {i}. {scenario['title']}",
                "",
                f"**Severity:** {scenario['severity']}",
                "",
                f"**Attack Vector:** {scenario['attack_vector']}",
                "",
                f"**Impact:** {scenario['impact']}",
                "",
                f"**Mitigation:** {scenario['mitigation']}",
                ""
            ])

        lines.extend([
            "## Architecture Diagram",
            "",
            self.generate_mermaid_diagram(threat_model),
            "",
            "---",
            "",
            "*Generated by AppSec-Sentinel Threat Modeling*"
        ])

        return "\n".join(lines)
