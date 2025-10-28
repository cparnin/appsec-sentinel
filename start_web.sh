#!/bin/bash
# AppSec AI Scanner - Web Interface Launcher
# Enhanced startup script with dependency checking and auto-browser launch

set -euo pipefail

echo "🔒 IX AppSec AI Scanner - Web Interface"
echo "=================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is in use
port_in_use() {
    lsof -ti:8000 >/dev/null 2>&1
}

# Select a supported Python interpreter (<= 3.12)
echo "🔍 Checking prerequisites..."

SUPPORTED_PYTHONS=(python3.12 python3.11 python3)
PYTHON_CMD=""

for candidate in "${SUPPORTED_PYTHONS[@]}"; do
    if command_exists "$candidate"; then
        if "$candidate" - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major == 3 and sys.version_info.minor <= 12) else 1)
PY
        then
            PYTHON_CMD="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ No supported Python interpreter found. Install Python 3.11 or 3.12 and retry."
    exit 1
fi

echo "✅ Using Python interpreter: $PYTHON_CMD ($($PYTHON_CMD --version | head -n1))"

# Ensure existing virtualenv uses a compatible interpreter
if [ -d ".venv" ] && [ -x ".venv/bin/python" ]; then
    if ! .venv/bin/python - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major == 3 and sys.version_info.minor <= 12) else 1)
PY
    then
        echo "⚠️  Existing .venv uses unsupported Python $(.venv/bin/python -c 'import sys; print(sys.version.split()[0])'). Recreating..."
        rm -rf .venv
    fi
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found. You'll need to add your API key:"
    echo "   cp env.example .env"
    echo "   # Then edit .env to add OPENAI_API_KEY or CLAUDE_API_KEY"
    echo ""
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    $PYTHON_CMD -m venv .venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment found"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Check and install dependencies
echo "📋 Ensuring Python dependencies are installed..."

pip install --upgrade pip >/dev/null 2>&1
pip install --upgrade -q -r requirements.txt -r requirements-web.txt 2>&1 | grep -v "already satisfied" | grep -v "Requirement already" || true

echo "✅ Python dependencies ready"

# Validate external scanners (Gitleaks/Trivy) are available
missing_tools=()
command_exists gitleaks || missing_tools+=("gitleaks")
command_exists trivy || missing_tools+=("trivy")

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "⚠️  Missing required CLI tools: ${missing_tools[*]}"
    echo "    Install them before running scans (see README)."
fi

# Check for code quality linters (optional but recommended)
echo "📊 Checking code quality linters (optional)..."
available_linters=()
missing_linters=()

# JavaScript/TypeScript - ESLint
if command_exists eslint; then
    available_linters+=("ESLint")
else
    missing_linters+=("eslint")
fi

# Python - Pylint (auto-install to venv)
if ! .venv/bin/python -c "import pylint" 2>/dev/null; then
    echo "   📦 Installing Pylint for Python code quality..."
    if .venv/bin/pip install pylint 2>&1 | grep -q "Successfully installed\|Requirement already satisfied"; then
        echo "   ✅ Pylint installed successfully"
        available_linters+=("Pylint")
    else
        echo "   ⚠️  Pylint installation failed - Python code quality scanning disabled"
        missing_linters+=("pylint")
    fi
else
    available_linters+=("Pylint")
fi

# Java - Checkstyle
if command_exists checkstyle || [ -n "$(find /usr/local -name 'checkstyle*.jar' 2>/dev/null | head -1)" ]; then
    available_linters+=("Checkstyle")
else
    missing_linters+=("checkstyle")
fi

# Go - golangci-lint
if command_exists golangci-lint; then
    available_linters+=("golangci-lint")
else
    missing_linters+=("golangci-lint")
fi

# Show what's available
if [ ${#available_linters[@]} -gt 0 ]; then
    echo "   ✅ Available: ${available_linters[*]}"
fi

# Show what's missing
if [ ${#missing_linters[@]} -gt 0 ]; then
    echo "   ⚠️  Missing (optional): ${missing_linters[*]}"
    echo "   💡 Install commands:"
    [[ " ${missing_linters[*]} " =~ " eslint " ]] && echo "      npm install -g eslint"
    [[ " ${missing_linters[*]} " =~ " checkstyle " ]] && echo "      brew install checkstyle  # macOS"
    [[ " ${missing_linters[*]} " =~ " golangci-lint " ]] && echo "      brew install golangci-lint  # macOS"
fi

echo ""

# Check if port is already in use
if port_in_use; then
    echo "⚠️  Port 8000 is already in use. Stopping existing process..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Display startup information
echo ""
echo "🌐 Web Interface will be available at:"
echo "   📱 http://localhost:8000"
echo "   🌍 http://$(ipconfig getifaddr en0 2>/dev/null || hostname):8000"
echo ""
echo "✨ Features:"
echo "   📁 Repository picker with auto-discovery"
echo "   🔍 SAST, Secrets, and Dependency scanning"
echo "   🤖 AI-powered auto-remediation"
echo "   📊 Visual reports and downloads"
echo ""
echo "🎯 Usage:"
echo "   1. Open http://localhost:8000 in your browser"
echo "   2. Click 'Browse Common Locations' or enter repo path"
echo "   3. Select scan level and auto-fix options"
echo "   4. Click 'Start Security Scan'"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"
echo "=================================="
echo ""

# Try to open browser automatically (macOS/Linux)
if command_exists open; then
    echo "🚀 Opening browser..."
    (sleep 3 && open http://localhost:8000) &
elif command_exists xdg-open; then
    echo "🚀 Opening browser..."
    (sleep 3 && xdg-open http://localhost:8000) &
else
    echo "💡 Manual: Open http://localhost:8000 in your browser"
fi

# Start the web server
echo "🔄 Starting web server..."
cd src && python web_app.py
