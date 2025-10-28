# Client Tool Exports

Drop JSON exports from existing security tools here for enhancement with AppSec-Sentinel's cross-file analysis.

## Quick Start

1. **Export from your security tool:**
```bash
# Snyk
snyk test --json > clients/client_exports/snyk_export.json

# SonarQube
curl "https://sonarqube.example.com/api/issues/search?componentKeys=myproject" \
  > clients/client_exports/sonar_export.json

# Veracode (export from web UI to JSON)
# Place in clients/client_exports/veracode_export.json
```

2. **Run ingestion + enhancement:**
```bash
cd /path/to/AppSec-Sentinel
python src/tool_ingestion.py
```

3. **Check enhanced results:**
- `outputs/report.html` - Full report with cross-file analysis
- `outputs/raw/{tool}_ingested.json` - Normalized + enhanced findings

## What Gets Enhanced

AppSec-Sentinel adds to existing findings:
- **Cross-file attack chains** - Traces vulnerabilities across multiple files
- **Framework context** - Understands Express, Django, Spring, Rails patterns
- **Business impact** - Risk assessment with cost estimates
- **AI remediation** - Actionable fix suggestions

## Supported Tools

### Native Support
- **Snyk** - API or JSON file
- **Veracode** - JSON file only
- **Checkmarx** - JSON export

### Generic JSON (any tool)
Any security tool with JSON export works with basic field mapping:
- `id`, `uuid` → Finding ID
- `title`, `name`, `rule` → Finding title
- `severity` → Normalized to CRITICAL/HIGH/MEDIUM/LOW
- `file`, `path` → File location
- `line`, `line_number` → Line number

## Example Workflow

```bash
# Client already uses Snyk
snyk test --json > clients/client_exports/snyk_export.json

# Enhance with AppSec-Sentinel
python src/tool_ingestion.py

# Now you have:
# - Original Snyk findings
# - + Cross-file attack chain analysis
# - + Framework-aware context
# - + AI remediation suggestions
```

## Notes

- This directory is gitignored (contains client data)
- Ingestion feature is **experimental** - not yet battle-tested
- For production use, test with sample data first
