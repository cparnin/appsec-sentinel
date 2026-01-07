# 🚀 AppSec-Sentinel Quickstart

## Installation

1.  **Clone & Setup**:
    ```bash
    git clone https://github.com/your-org/appsec-sentinel.git
    cd appsec-sentinel
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Install Scanners**:
    The core scanners must be installed on your system path.

    **macOS (Homebrew)**:
    ```bash
    brew install gitleaks trivy
    pip install semgrep  # Installed via requirements.txt, but good to verify
    ```

    **Linux/Windows**:
    *   [Gitleaks Installation](https://github.com/gitleaks/gitleaks#installation)
    *   [Trivy Installation](https://aquasecurity.github.io/trivy/v0.18.3/installation/)

## Configuration

1.  **Environment Variables**:
    Copy `.env.example` to `.env` and set your keys:
    ```bash
    cp .env.example .env
    # Edit .env:
    # OPENAI_API_KEY=sk-... (or GEMINI_API_KEY / CLAUDE_API_KEY)
    # APPSEC_SCAN_LEVEL=critical-high
    ```

## Usage

### Interactive Mode (CLI)
Run the scanner interactively to select a repo and tools:
```bash
python3 src/main.py
```
*or use the helper script:*
```bash
./start_cli.sh
```

### CI/CD Mode (GitHub Actions)
The scanner automatically detects CI/CD environments.
```yaml
- name: Security Scan
  run: python3 src/main.py
  env:
    APPSEC_AUTO_FIX: "true"
```

### Web Interface
Start the local web UI:
```bash
./start_web.sh
# Open http://localhost:8000
```

