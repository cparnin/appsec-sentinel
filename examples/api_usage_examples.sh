#!/bin/bash
# AppSec-Sentinel API Usage Examples
# These are simple curl commands that show how to use the REST API

echo "🌐 AppSec-Sentinel REST API Examples"
echo "====================================="
echo ""

# Make sure web server is running first: ./start_web.sh
# Then run these commands in a separate terminal

echo "1. 🔍 Run a security scan"
echo "-------------------------"
cat << 'EOF'
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/your/repo",
    "scan_level": "critical-high",
    "selected_tools": ["semgrep", "trivy", "gitleaks"]
  }'
EOF
echo ""
echo ""

echo "2. 🛡️ Generate threat model"
echo "-------------------------"
cat << 'EOF'
curl -X POST http://localhost:8000/threat-model \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/your/repo"
  }'
EOF
echo ""
echo ""

echo "3. 📄 Get HTML report"
echo "-------------------"
cat << 'EOF'
curl http://localhost:8000/report > security_report.html
open security_report.html  # macOS
# or: xdg-open security_report.html  # Linux
EOF
echo ""
echo ""

echo "4. 📊 Download SBOM"
echo "-----------------"
cat << 'EOF'
curl http://localhost:8000/reports/sbom.cyclonedx.json > sbom.json
EOF
echo ""
echo ""

echo "💡 Real-world use case:"
echo "---------------------"
echo "You could build a dashboard that calls these APIs to:"
echo "  - Scan all repos nightly"
echo "  - Display security metrics"
echo "  - Generate threat models on-demand"
echo "  - Track vulnerabilities over time"
echo ""
echo "The API lets OTHER PROGRAMS use AppSec-Sentinel without a human clicking buttons!"
