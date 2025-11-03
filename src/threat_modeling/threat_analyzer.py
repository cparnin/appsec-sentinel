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

    def __init__(self, repo_path: str, max_files: int = None):
        self.repo_path = Path(repo_path)
        self.threats = []
        self.components = []
        self.entry_points = []
        self.data_stores = []
        self.trust_boundaries = []
        # Allow customization via env var or constructor parameter
        # Default: 1000 files - with optimizations, this is still very fast (< 1 sec for most repos)
        # Thanks to 100KB partial reads and file size checks, we can scan more files without slowdown
        self.max_files = max_files or int(os.environ.get('THREAT_MODEL_MAX_FILES', '1000'))
        # Cache for file contents to avoid re-reading same files
        self._file_content_cache = {}
        # Max file size to read (skip large files that are likely build artifacts)
        self._max_file_size_bytes = 1024 * 1024  # 1MB
        # Max content to read for pattern matching (first 100KB is usually enough)
        self._max_read_size = 100 * 1024  # 100KB

        # Route extraction patterns (method, path)
        self.route_patterns = {
            'express': [
                (r'app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', 'method_path'),
                (r'router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', 'method_path'),
            ],
            'flask': [
                (r'@app\.route\([\'"]([^\'"]+)[\'"].*?methods=\[(.*?)\]', 'path_methods'),
                (r'@app\.route\([\'"]([^\'"]+)[\'"]', 'path_only'),
            ],
            'django': [
                (r'path\([\'"]([^\'"]+)[\'"]', 'path_only'),
            ],
            'spring': [
                (r'@RequestMapping\([\'"]([^\'"]+)[\'"]', 'path_only'),
                (r'@(Get|Post|Put|Delete|Patch)Mapping\([\'"]([^\'"]+)[\'"]', 'method_path'),
            ],
            'laravel': [
                (r'Route::(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', 'method_path'),
            ],
            'fastapi': [
                (r'@app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', 'method_path'),
            ]
        }

        # Database type detection patterns
        self.database_patterns = {
            'PostgreSQL': ['pg', 'postgres', 'PostgreSQL', 'psycopg2', 'asyncpg'],
            'MySQL': ['mysql', 'MySQL', 'mysqlclient', 'pymysql'],
            'MongoDB': ['mongoose', 'mongodb', 'MongoClient', 'pymongo'],
            'Redis': ['redis', 'Redis', 'ioredis'],
            'SQLite': ['sqlite3', 'SQLite'],
            'MSSQL': ['mssql', 'SQL Server', 'pyodbc', 'tedious'],
            'Oracle': ['oracle', 'cx_Oracle', 'oracledb'],
            'Cassandra': ['cassandra', 'pycassa'],
        }

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
        files_scanned = 0
        MAX_FILES_TO_SCAN = self.max_files  # Configurable limit to prevent hanging on large repos
        early_exit_triggered = False

        # Skip directories (used with os.walk for fast traversal)
        skip_dirs = {
            'node_modules', '.git', 'vendor', 'venv', '.venv', 'dist', 'build', '__pycache__',
            'coverage', '.pytest_cache', '.mypy_cache', '.tox', 'htmlcov', 'site-packages',
            'bower_components', 'jspm_packages', '.next', '.nuxt', 'out', 'target',
            'bin', 'obj', 'packages', '.gradle', '.idea', '.vscode', 'logs', 'tmp', 'temp'
        }

        # Extensions to scan
        target_extensions = {'.js', '.ts', '.py', '.java', '.rb', '.php', '.go', '.rs'}

        print(f"🔍 Starting architecture discovery (max {MAX_FILES_TO_SCAN} files)...")

        # Use os.walk for much faster traversal with directory pruning
        for root, dirs, files in os.walk(self.repo_path):
            # CRITICAL: Prune directories in-place to avoid traversing them
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for filename in files:
                # Check file extension
                if not any(filename.endswith(ext) for ext in target_extensions):
                    continue

                # Stop if we've scanned enough files
                if files_scanned >= MAX_FILES_TO_SCAN:
                    print(f"⚠️  Reached file scan limit ({MAX_FILES_TO_SCAN} files)")
                    early_exit_triggered = True
                    break

                # Early exit if we have enough information
                if (len(detected_frameworks) >= 3 and
                    len(self.entry_points) >= 20 and
                    len(self.data_stores) >= 5):
                    early_exit_triggered = True
                    print(f"✓ Sufficient architecture data collected: {len(detected_frameworks)} frameworks, {len(self.entry_points)} endpoints, {len(self.data_stores)} data stores")
                    break

                files_scanned += 1
                file_path = Path(root) / filename

                # Progress logging every 25 files
                if files_scanned % 25 == 0:
                    print(f"   📄 Scanned {files_scanned} files... (found {len(detected_frameworks)} frameworks, {len(self.entry_points)} endpoints)")

                try:
                    # Skip files that are too large (likely build artifacts or minified code)
                    file_size = file_path.stat().st_size
                    if file_size > self._max_file_size_bytes:
                        continue

                    # Read only first 100KB for pattern matching (sufficient for architecture detection)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(self._max_read_size)

                    # Cache content for potential reuse
                    cache_key = str(file_path.relative_to(self.repo_path))
                    self._file_content_cache[cache_key] = content

                    # Detect frameworks and extract routes
                    for fw, patterns in frameworks.items():
                        if any(p in content for p in patterns):
                            if fw not in detected_frameworks:
                                detected_frameworks.append(fw)

                            # Extract specific routes for this framework
                            routes = self._extract_routes(content, fw)
                            if routes:
                                # Store component with route details
                                comp_name = self._get_component_name(cache_key)
                                self.components.append({
                                    'name': comp_name,
                                    'type': 'controller',
                                    'framework': fw.title(),
                                    'file': cache_key,
                                    'routes': routes
                                })

                                # Also add to entry points with route info
                                self.entry_points.append({
                                    'file': cache_key,
                                    'type': 'http_endpoint',
                                    'framework': fw,
                                    'routes': routes
                                })

                    # Detect data stores with specific database types
                    db_type = self._detect_database_type(content)
                    if db_type or any(p in content for p in ['mongoose.', 'Sequelize', 'models.Model', 'JpaRepository', 'ActiveRecord', 'PDO', 'sql.DB']):
                        if cache_key not in [d['file'] for d in self.data_stores]:
                            self.data_stores.append({
                                'file': cache_key,
                                'type': db_type or 'database',
                                'name': self._extract_db_name(content)
                            })

                except Exception:
                    continue

            if early_exit_triggered:
                break

        # Log scanning results
        print(f"📊 Architecture discovery: scanned {files_scanned} files, found {len(detected_frameworks)} frameworks, {len(self.entry_points)} endpoints, {len(self.data_stores)} data stores")

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
        """Identify user input handlers (uses cached file contents when available)"""
        handlers = set()

        # Input handler patterns
        input_patterns = ['req.body', 'request.form', 'request.POST', 'request.GET',
                         '@RequestBody', 'params[:' , '$_POST', '$_GET', 'ctx.request.body']

        # First, check cached files from architecture discovery
        for cache_key, content in self._file_content_cache.items():
            if any(p in content for p in input_patterns):
                handlers.add(cache_key)

            # Stop if we have enough
            if len(handlers) >= 10:
                return list(handlers)[:10]

        # If we need more, scan additional files (but this should be rare now)
        if len(handlers) < 10:
            files_scanned = 0
            MAX_FILES = 50  # Reduced since we already have cache

            # Skip directories
            skip_dirs = {
                'node_modules', '.git', 'vendor', 'venv', '.venv', 'dist', 'build', '__pycache__',
                'coverage', '.pytest_cache', '.mypy_cache', '.tox', 'htmlcov', 'site-packages',
                'bower_components', 'jspm_packages', '.next', '.nuxt', 'out', 'target',
                'bin', 'obj', 'packages', '.gradle', '.idea', '.vscode', 'logs', 'tmp', 'temp'
            }

            # Use os.walk for fast traversal
            for root, dirs, files in os.walk(self.repo_path):
                # Prune directories in-place
                dirs[:] = [d for d in dirs if d not in skip_dirs]

                for filename in files:
                    # Check extension
                    if not any(filename.endswith(ext) for ext in ['.js', '.ts', '.py', '.java', '.rb', '.php']):
                        continue

                    # Stop if we have enough
                    if files_scanned >= MAX_FILES or len(handlers) >= 10:
                        break

                    file_path = Path(root) / filename
                    cache_key = str(file_path.relative_to(self.repo_path))

                    # Skip if already in cache
                    if cache_key in self._file_content_cache:
                        continue

                    files_scanned += 1

                    try:
                        # Skip large files
                        file_size = file_path.stat().st_size
                        if file_size > self._max_file_size_bytes:
                            continue

                        # Read only first 100KB
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(self._max_read_size)

                        if any(p in content for p in input_patterns):
                            handlers.add(cache_key)

                    except Exception:
                        continue

                if files_scanned >= MAX_FILES or len(handlers) >= 10:
                    break

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

    def _extract_routes(self, content: str, framework: str) -> List[Dict[str, str]]:
        """Extract specific route URLs from file content"""
        import re
        routes = []

        if framework not in self.route_patterns:
            return routes

        for pattern, pattern_type in self.route_patterns[framework]:
            try:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    if pattern_type == 'method_path':
                        # Groups: (method, path)
                        method = match.group(1).upper()
                        path = match.group(2)
                        routes.append({'method': method, 'path': path})
                    elif pattern_type == 'path_methods':
                        # Groups: (path, methods)
                        path = match.group(1)
                        methods_str = match.group(2)
                        # Parse methods array like ['GET', 'POST']
                        methods = [m.strip().strip('"\'') for m in methods_str.split(',')]
                        for method in methods:
                            routes.append({'method': method.upper(), 'path': path})
                    elif pattern_type == 'path_only':
                        # Group: (path)
                        path = match.group(1)
                        routes.append({'method': 'ALL', 'path': path})
            except Exception:
                continue

        # Limit to 10 routes per file to avoid overwhelming diagram
        return routes[:10]

    def _get_component_name(self, file_path: str) -> str:
        """Extract readable component name from file path"""
        # Get filename without extension
        filename = file_path.split('/')[-1].rsplit('.', 1)[0]

        # Remove common suffixes
        for suffix in ['Controller', 'Service', 'Handler', 'Router', 'Routes', 'View']:
            if filename.endswith(suffix):
                return filename

        return filename

    def _detect_database_type(self, content: str) -> str:
        """Detect database type from content"""
        for db_type, patterns in self.database_patterns.items():
            if any(p in content for p in patterns):
                return db_type
        return None

    def _extract_db_name(self, content: str) -> str:
        """Try to extract database name from connection strings"""
        import re

        # Common database name patterns in connection strings
        patterns = [
            r'database["\']?\s*[=:]\s*["\']([^"\']+)["\']',  # database='mydb'
            r'db["\']?\s*[=:]\s*["\']([^"\']+)["\']',  # db: 'mydb'
            r'/([a-zA-Z0-9_]+)(?:\?|$)',  # mongodb://localhost/mydb
            r'Database=([^;]+)',  # SQL Server
        ]

        for pattern in patterns:
            try:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
            except Exception:
                continue

        return 'default'

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped"""
        skip_dirs = {
            'node_modules', '.git', 'vendor', 'venv', '.venv', 'dist', 'build', '__pycache__',
            'coverage', '.pytest_cache', '.mypy_cache', '.tox', 'htmlcov', 'site-packages',
            'bower_components', 'jspm_packages', '.next', '.nuxt', 'out', 'target',
            'bin', 'obj', 'packages', '.gradle', '.idea', '.vscode', 'logs', 'tmp', 'temp'
        }
        return any(skip_dir in path.parts for skip_dir in skip_dirs)

    def _get_file_severity_color(self, file_path: str, threat_model: Dict) -> str:
        """Get Mermaid styling class based on vulnerability severity in file"""
        # Map findings to files by checking STRIDE categories
        file_severities = []

        for category, threats in threat_model.get('stride_analysis', {}).items():
            for threat in threats:
                # Check if this threat is related to this file
                # (STRIDE threats don't have file paths, so this is best-effort)
                threat_file = threat.get('finding', '').lower()
                if file_path.lower() in threat_file or any(part in threat_file for part in file_path.split('/')):
                    file_severities.append(threat.get('severity', 'LOW'))

        # Also check threat scenarios
        for scenario in threat_model.get('threat_scenarios', []):
            # Scenarios might have file info in title or attack_vector
            if file_path in str(scenario):
                file_severities.append(scenario.get('severity', 'LOW'))

        # Determine highest severity
        if 'CRITICAL' in file_severities:
            return 'fill:#ff6b6b,stroke:#c92a2a,stroke-width:3px'  # Red
        elif 'HIGH' in file_severities:
            return 'fill:#ffa94d,stroke:#e67700,stroke-width:2px'  # Orange
        elif 'MEDIUM' in file_severities:
            return 'fill:#ffe066,stroke:#e8b600,stroke-width:2px'  # Yellow
        elif 'LOW' in file_severities:
            return 'fill:#74c0fc,stroke:#339af0,stroke-width:1px'  # Blue

        # No vulnerabilities detected in this file
        return 'fill:#d3f9d8,stroke:#51cf66,stroke-width:1px'  # Green

    def generate_mermaid_diagram(self, threat_model: Dict) -> str:
        """Generate enhanced Mermaid architecture diagram with specific details"""

        lines = [
            "```mermaid",
            "graph TB",
            "    User[External User]",
        ]

        # Add components with specific details
        components = threat_model['architecture']['components']
        entry_points = threat_model['architecture']['entry_points']

        # Group components by framework for better organization
        framework_components = defaultdict(list)
        for comp in components:
            framework = comp.get('framework', 'Application')
            framework_components[framework].append(comp)

        # Create component nodes with route information
        comp_id_map = {}
        comp_counter = 0

        for framework, comps in framework_components.items():
            for comp in comps[:5]:  # Limit to 5 per framework to avoid clutter
                comp_id = f"C{comp_counter}"
                comp_id_map[comp['file']] = comp_id

                # Build component label with routes
                label = f"{comp['name']}"
                if 'routes' in comp and comp['routes']:
                    # Show first 3 routes
                    route_strs = []
                    for route in comp['routes'][:3]:
                        route_str = f"{route.get('method', 'ALL')} {route.get('path', '/')}"
                        route_strs.append(route_str)
                    routes_display = '<br/>'.join(route_strs)
                    label = f"{comp['name']}<br/><small>{routes_display}</small>"

                # Shorten file path for display
                file_short = '/'.join(comp['file'].split('/')[-2:])
                label = f"{comp['name']}<br/><small>{file_short}</small>"

                lines.append(f"    {comp_id}[\"{label}\"]")
                comp_counter += 1

        # Add data stores with specific database types
        data_stores = threat_model['architecture']['data_stores']
        db_id_map = {}

        for i, ds in enumerate(data_stores[:5]):  # Limit to 5 databases
            ds_id = f"DB{i}"
            db_id_map[ds['file']] = ds_id

            # Use specific database type
            db_type = ds.get('type', 'Database')
            db_name = ds.get('name', 'default')

            # Create descriptive label
            if db_name and db_name != 'default':
                label = f"{db_type}<br/>{db_name}"
            else:
                label = db_type

            lines.append(f"    {ds_id}[(\"{label}\")]")

        # Add connections from user to endpoints
        lines.append("")
        lines.append("    %% User requests to endpoints")

        # Connect user to each unique component
        added_connections = set()
        for ep in entry_points[:10]:  # Limit to 10 entry points
            comp_file = ep['file']
            if comp_file in comp_id_map:
                comp_id = comp_id_map[comp_file]
                if comp_id not in added_connections:
                    # Show route info on connection if available
                    if 'routes' in ep and ep['routes']:
                        route = ep['routes'][0]  # Show first route
                        method = route.get('method', 'HTTP')
                        path = route.get('path', '/')
                        lines.append(f"    User -->|{method} {path}| {comp_id}")
                    else:
                        lines.append(f"    User -->|HTTP Request| {comp_id}")
                    added_connections.add(comp_id)

        # Connect components to databases
        if comp_id_map and db_id_map:
            lines.append("")
            lines.append("    %% Component to database connections")
            # Connect first few components to first database (simplified)
            for comp_id in list(comp_id_map.values())[:3]:
                for db_id in list(db_id_map.values())[:1]:
                    lines.append(f"    {comp_id} -->|Query| {db_id}")

        # Add trust boundaries with components
        lines.append("")
        lines.append("    subgraph TB1[Trust Boundary: Internet]")
        lines.append("        User")
        lines.append("    end")
        lines.append("")

        if comp_id_map:
            lines.append("    subgraph TB2[Trust Boundary: Application]")
            for comp_id in comp_id_map.values():
                lines.append(f"        {comp_id}")
            lines.append("    end")
            lines.append("")

        if db_id_map:
            lines.append("    subgraph TB3[Trust Boundary: Data Layer]")
            for db_id in db_id_map.values():
                lines.append(f"        {db_id}")
            lines.append("    end")

        # Apply vulnerability severity styling to components
        lines.append("")
        lines.append("    %% Vulnerability severity styling")
        for file_path, comp_id in comp_id_map.items():
            style = self._get_file_severity_color(file_path, threat_model)
            lines.append(f"    style {comp_id} {style}")

        # Style databases as neutral
        for db_id in db_id_map.values():
            lines.append(f"    style {db_id} fill:#e7f5ff,stroke:#1971c2,stroke-width:2px")

        # Style user as external entity
        lines.append(f"    style User fill:#fff3bf,stroke:#f59f00,stroke-width:2px")

        # Add legend/note about color coding
        lines.append("")
        lines.append("    %% Legend:")
        lines.append("    %% Red = Critical vulnerabilities")
        lines.append("    %% Orange = High severity")
        lines.append("    %% Yellow = Medium severity")
        lines.append("    %% Blue = Low severity")
        lines.append("    %% Green = No vulnerabilities detected")

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
