# Threat Modeling

Automated threat analysis using STRIDE framework, architecture mapping, and attack surface assessment.

## What It Does

Generates comprehensive threat models by:

1. **Architecture Discovery** - Identifies components, frameworks, entry points, and data stores
2. **STRIDE Analysis** - Maps security findings to threat categories
3. **Attack Surface Mapping** - Quantifies external-facing risks
4. **Trust Boundary Identification** - Highlights security control points
5. **Threat Scenario Generation** - Creates actionable threat descriptions
6. **Visual Diagrams** - Generates Mermaid architecture diagrams

## Output

Threat models are saved to: `outputs/{repo}/{branch}/`

- **threat_model.json** - Structured threat data
- **THREAT_MODEL.md** - Human-readable report
- **architecture.mermaid** - Visual architecture diagram

## Usage

### CLI

```bash
./start_cli.sh
# Select "Generate Threat Model" from menu
```

### Web Interface

```bash
./start_web.sh
# POST to /threat-model endpoint with repo_path
```

### MCP (Claude Desktop)

```
"Generate a threat model for nodejs-goof"
```

### Python API

```python
from threat_modeling import ThreatAnalyzer

# Create analyzer
analyzer = ThreatAnalyzer('/path/to/repo')

# Generate threat model
threat_model = analyzer.analyze(security_findings)

# Export to files
analyzer.export_threat_model(threat_model, 'outputs/my-repo/main')
```

## STRIDE Framework

Threats are categorized using Microsoft's STRIDE model:

- **Spoofing** - Authentication bypass, credential theft
- **Tampering** - SQL injection, XSS, CSRF, path traversal
- **Repudiation** - Missing audit logs, insufficient tracking
- **Information Disclosure** - Exposed secrets, data leakage
- **Denial of Service** - Resource exhaustion, regex DoS
- **Elevation of Privilege** - Command injection, RCE, XXE

## Architecture Components

### Auto-Detected Elements

**Frameworks:**
- Express, Flask, Django, Spring, Rails, Laravel, FastAPI

**Entry Points:**
- HTTP endpoints (routes, controllers, APIs)
- User input handlers (forms, query params, request bodies)

**Data Stores:**
- Databases (MongoDB, PostgreSQL, MySQL, SQLite)
- ORM layers (Sequelize, Mongoose, JPA, ActiveRecord)

**External Dependencies:**
- npm, pip, Maven, Bundler packages

### Trust Boundaries

Automatically identified security control points:

1. **External → Application** - User requests crossing into system
2. **Application → Database** - Data layer access
3. **Application → Third-party Services** - External API calls

Each boundary includes:
- Risk level (HIGH/MEDIUM/LOW)
- Required security controls
- Recommended mitigations

## Attack Surface Scoring

Calculates exposure based on:

- HTTP endpoint count (weight: 2x)
- Data store count (weight: 10x)
- External dependency count (weight: 1x)

**Score Ranges:**
- **HIGH** (70+) - Large attack surface, extensive entry points
- **MEDIUM** (40-69) - Moderate exposure
- **LOW** (<40) - Minimal external facing components

## Threat Scenarios

Generates concrete attack scenarios including:

- **Attack Vector** - How the attack is executed
- **Impact** - Consequences of successful exploitation
- **Severity** - CRITICAL/HIGH/MEDIUM/LOW
- **Mitigation** - Remediation recommendations

Scenarios are prioritized by severity (Critical → High → Medium → Low).

## Integration with Security Scans

Threat modeling enhances security scan results by:

1. **Mapping findings to STRIDE** - Categorizes vulnerabilities by threat type
2. **Architecture context** - Shows where vulnerabilities exist in system design
3. **Attack chain visualization** - Connects entry points to vulnerable components
4. **Business impact** - Relates threats to real-world attack scenarios

Best practice: Run security scan first, then generate threat model.

## Example Output

### Summary
```
Total Threats Identified: 47
Attack Surface Risk: HIGH
Overall Risk Level: HIGH

STRIDE Breakdown:
- Spoofing: 3
- Tampering: 18
- Repudiation: 1
- Information Disclosure: 22
- Denial of Service: 0
- Elevation of Privilege: 3
```

### Architecture Diagram
```mermaid
graph TB
    User[External User]
    C0[Express]
    DB0[(Database)]

    User -->|HTTP Request| C0
    C0 -->|Query| DB0

    subgraph TB1[Trust Boundary: Internet]
        User
    end

    subgraph TB2[Trust Boundary: Application]
        C0
    end

    subgraph TB3[Trust Boundary: Data Layer]
        DB0
    end
```

### Threat Scenario Example
```
Title: SQL Injection in User Login
Severity: CRITICAL

Attack Vector: Attacker supplies malicious input that gets executed as code

Impact: Complete system compromise, data breach, or service disruption

Mitigation: Use parameterized queries and input validation
```

## When to Generate Threat Models

**Ideal Use Cases:**

- ✅ New application/feature development
- ✅ Security architecture reviews
- ✅ Pre-deployment risk assessments
- ✅ Compliance requirements (SOC2, ISO 27001)
- ✅ Post-incident analysis
- ✅ Third-party code reviews

**Frequency:**

- **Initial:** At project inception
- **Regular:** After major feature additions
- **Triggered:** When high-severity findings detected
- **Compliance:** Quarterly or per audit schedule

**NOT Recommended For:**

- ❌ **CI/CD Pipelines** - Threat models don't change every commit; use on-demand instead
- ❌ **Every Pull Request** - Adds noise without value; better for strategic reviews
- ❌ **Hot-path Critical Builds** - Use for architecture changes, not routine code changes

**Best Practice:** Run vulnerability scans in CI/CD (automated). Run threat modeling on-demand via CLI/Web/MCP (strategic).

## Architecture

### Processing Flow

```
Repository
    ↓
Framework Detection
    ↓
Component Discovery
    ↓
Entry Point Mapping
    ↓
Trust Boundary Identification
    ↓
STRIDE Analysis (with scan findings)
    ↓
Threat Scenario Generation
    ↓
Export (JSON + Markdown + Mermaid)
```

### Integration Points

- **src/main.py** - CLI threat model command
- **src/web_app.py** - `/threat-model` endpoint
- **mcp/appsec_mcp_server.py** - `generate_threat_model` tool

### File Structure

```
src/threat_modeling/
  ├── __init__.py
  └── threat_analyzer.py       # Core threat modeling engine

outputs/{repo}/{branch}/
  ├── threat_model.json         # Structured data
  ├── THREAT_MODEL.md           # Human-readable report
  └── architecture.mermaid      # Visual diagram
```

## Configuration

No configuration required - works out-of-the-box.

**Optional:** Combine with security scans for enhanced analysis:

```bash
# CLI: Run full scan + threat model
./start_cli.sh
# 1. Select "Run Security Scan"
# 2. Select "Generate Threat Model"

# Web: Sequential requests
curl -X POST http://localhost:8000/scan -d '{"repo_path": "/path/to/repo"}'
curl -X POST http://localhost:8000/threat-model -d '{"repo_path": "/path/to/repo"}'
```

## Limitations

- **Static Analysis Only** - Does not discover runtime behavior
- **Framework Detection** - May miss custom or uncommon frameworks
- **Dependency Depth** - Counts direct dependencies only
- **Language Coverage** - Best support for JS/TS, Python, Java, Go, Ruby, PHP

## Best Practices

1. **Run After Security Scans** - Threat model benefits from vulnerability context
2. **Review Manually** - Automated analysis is a starting point, not complete
3. **Update Regularly** - Regenerate after architectural changes
4. **Document Mitigations** - Track which threats have been addressed
5. **Share with Team** - Use THREAT_MODEL.md for security discussions

## FAQ

**Q: How is this different from vulnerability scanning?**

A: Vulnerability scanning finds specific bugs. Threat modeling identifies architectural risks and attack patterns before they become vulnerabilities.

**Q: Do I need security expertise?**

A: No. Threat models are generated automatically with plain-English explanations. Security review is recommended but not required.

**Q: Does this replace manual threat modeling?**

A: No. It accelerates threat modeling by automating discovery and categorization. Manual review adds business context and custom threats.

**Q: Can I customize STRIDE categories?**

A: Currently uses standard STRIDE. Custom threat frameworks can be added by extending `ThreatAnalyzer`.

**Q: How accurate is framework detection?**

A: Very accurate for major frameworks (Express, Flask, Spring, etc.). May miss custom or proprietary frameworks.

**Q: What about microservices?**

A: Run threat modeling per service. Each microservice gets its own threat model showing its attack surface and internal threats.

## Contributing

Contributions welcome! Areas for enhancement:

- Additional framework detection patterns
- Custom threat framework support (PASTA, VAST, etc.)
- Enhanced diagram generation
- Integration with threat intelligence feeds
- Machine learning for threat prioritization

---

**Version:** 1.0.0
**Last Updated:** 2025-01-31
**Status:** Production Ready
