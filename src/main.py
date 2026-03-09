#!/usr/bin/env python3
"""
AppSec-Sentinel - Entry Point

Thin entry point that delegates to:
- cli.py: Interactive prompts and menus
- orchestrator.py: Scan execution, reporting, and SBOM generation
- scanners/validation.py: Input validation (single source of truth)

Usage:
    python main.py              # Interactive mode
    GITHUB_ACTIONS=true python main.py  # CI/CD auto mode
"""

# Load environment variables early
from dotenv import load_dotenv
load_dotenv()

from pathlib import Path
import logging
import os
import asyncio
import json
from typing import Any

# Setup logging early
from logging_config import setup_logging, get_logger, set_debug_mode
setup_logging(level=os.getenv('APPSEC_LOG_LEVEL', 'INFO'))

# Reduce noise from third-party libraries
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("openai").setLevel(logging.ERROR)
logging.getLogger("anthropic").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)

logger = get_logger(__name__)

# Import configuration
from config import BASE_OUTPUT_DIR
from path_utils import get_output_path, cleanup_old_scans, setup_output_directories
from scanners.validation import validate_repo_path as _validate_repo_path

# Import orchestrator (scan pipeline, reporting)
from orchestrator import run_full_scan_pipeline

# Import CLI interaction
from cli import (
    show_interactive_menu,
    select_scan_level,
    select_tools,
    select_repository,
)


def validate_repo_path(repo_path: str) -> Path:
    """Validate repository path, raising on failure."""
    result = _validate_repo_path(repo_path, raise_on_error=True)
    if result is None:
        raise ValueError(f"Repository path validation failed: {repo_path}")
    return result


def validate_environment_config() -> dict[str, Any]:
    """
    Validate environment configuration and return sanitized values.

    Ensures environment variables are properly formatted and within
    acceptable ranges to prevent configuration-related issues.
    """
    config: dict[str, Any] = {}

    # Validate timeouts (must be positive integers)
    timeout_vars = {
        'SEMGREP_TIMEOUT': (300, 60, 1800),
        'GITLEAKS_TIMEOUT': (120, 30, 600),
        'TRIVY_TIMEOUT': (300, 60, 1800),
    }
    for var, (default, min_val, max_val) in timeout_vars.items():
        try:
            value = int(os.getenv(var, default))
            if value < min_val or value > max_val:
                logger.warning(f"{var} value {value} out of range [{min_val}-{max_val}], using default {default}")
                value = default
            config[var.lower()] = value
        except ValueError:
            logger.warning(f"Invalid {var} value, using default {default}")
            config[var.lower()] = default

    # Validate AI provider
    ai_provider = os.getenv('AI_PROVIDER', 'openai').strip().lower()
    if ai_provider not in ['openai', 'claude', 'aws_bedrock']:
        logger.warning(f"Unsupported AI provider '{ai_provider}', defaulting to 'openai'")
        ai_provider = 'openai'
    config['ai_provider'] = ai_provider

    if ai_provider == 'aws_bedrock':
        aws_region = os.getenv('AWS_REGION', '').strip()
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID', '').strip()
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '').strip()
        logger.info("AWS Bedrock configuration check:")
        logger.info(f"  - AWS_REGION: {'set' if aws_region else 'not set (will default to us-east-1)'}")
        logger.info(f"  - AWS_ACCESS_KEY_ID: {'set' if aws_access_key else 'not set'}")
        logger.info(f"  - AWS_SECRET_ACCESS_KEY: {'set' if aws_secret_key else 'not set'}")
        if not aws_access_key or not aws_secret_key:
            logger.error("AWS credentials are required for Bedrock but not found in environment")

    # Validate scan level
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high').strip().lower()
    if scan_level not in ['critical-high', 'all']:
        logger.warning(f"Invalid scan level '{scan_level}', defaulting to 'critical-high'")
        scan_level = 'critical-high'
    config['scan_level'] = scan_level

    # Validate hourly rate
    try:
        hourly_rate = float(os.getenv('SECURITY_ENGINEER_HOURLY_RATE', '150'))
        if hourly_rate <= 0 or hourly_rate > 1000:
            hourly_rate = 150.0
        config['hourly_rate'] = hourly_rate
    except ValueError:
        config['hourly_rate'] = 150.0

    # Validate API keys (presence only, never log values)
    for key_var in ['OPENAI_API_KEY', 'CLAUDE_API_KEY']:
        key_value = os.getenv(key_var, '').strip()
        if key_value:
            if len(key_value) < 10:
                logger.warning(f"{key_var} appears too short to be valid")
            elif '\n' in key_value or '\r' in key_value:
                logger.warning(f"{key_var} contains invalid characters")
            else:
                config[key_var.lower()] = True
        else:
            config[key_var.lower()] = False

    return config


def is_github_actions() -> bool:
    """Check if running in GitHub Actions environment."""
    return os.getenv('GITHUB_ACTIONS') == 'true'


# ---------------------------------------------------------------------------
# Auto-remediation
# ---------------------------------------------------------------------------

def handle_auto_remediation(
    repo_path: str,
    all_findings: list[dict[str, Any]],
    auto_choice: int | None = None,
) -> dict:
    """Handle auto-remediation flow for findings."""
    total_findings = len(all_findings)
    critical_findings = len([f for f in all_findings if f.get('severity', '').lower() == 'critical'])
    high_findings = len([f for f in all_findings if f.get('severity', '').lower() in ['high', 'error']])

    print("\n📊 Scan Results:")
    print(f"   Total findings: {total_findings}")
    print(f"   Critical: {critical_findings}")
    print(f"   High: {high_findings}")

    if total_findings == 0:
        print("🎉 No security issues found! Your code looks clean.")
        return {"success": True, "message": "No vulnerabilities found"}

    sast_findings = [f for f in all_findings if f.get('tool') in ['semgrep', 'gitleaks']]
    dependency_findings = [f for f in all_findings if f.get('tool') == 'trivy' and f.get('fixed_version')]
    secrets_count = len([f for f in all_findings if f.get('tool') == 'gitleaks'])
    semgrep_count = len([f for f in all_findings if f.get('tool') == 'semgrep'])

    if not sast_findings and not dependency_findings:
        print("\n💡 No auto-fixable vulnerabilities found in this scan.")
        return {"success": True, "message": "No auto-fixable vulnerabilities found"}

    # Display options
    print("\n🔧 Auto-Remediation Options:")
    if sast_findings:
        if semgrep_count > 0 and secrets_count > 0:
            print(f"   Found {semgrep_count} SAST vulnerabilities (auto-fixable) + {secrets_count} secrets (manual review required)")
        elif semgrep_count > 0:
            print(f"   Found {semgrep_count} SAST vulnerabilities that might be auto-fixable")
        elif secrets_count > 0:
            print(f"   Found {secrets_count} secrets detected (manual review required)")

    total_deps = len([f for f in all_findings if f.get('tool') == 'trivy'])
    if dependency_findings:
        print(f"   Found {len(dependency_findings)} auto-fixable dependency vulnerabilities ({total_deps} total dependencies)")

    if sast_findings and dependency_findings:
        print("   [1] Auto-fix code issues (SAST) + flag secrets")
        print("   [2] Auto-fix dependencies only")
        print("   [3] Auto-fix both (creates 2 separate PRs)")
        print("   [4] Skip auto-fix")
    elif sast_findings:
        print("   [1] Auto-fix code issues (SAST) + flag secrets")
        print("   [4] Skip auto-fix")
    elif dependency_findings:
        print("   [2] Auto-fix dependencies only")
        print("   [4] Skip auto-fix")

    # Determine choice
    choice = _determine_remediation_choice(auto_choice, sast_findings, dependency_findings)

    # Execute
    if choice == '4':
        return {"success": True, "message": "Auto-fix skipped"}

    return _execute_remediation(repo_path, choice, sast_findings, dependency_findings,
                                semgrep_count, secrets_count)


def _determine_remediation_choice(
    auto_choice: int | None,
    sast_findings: list,
    dependency_findings: list,
) -> str:
    """Determine which remediation option to use."""
    if auto_choice is not None:
        choice = str(auto_choice)
        print(f"🤖 Automated mode: Using option {choice}")
        return choice

    if is_github_actions() or os.getenv('APPSEC_WEB_MODE', 'false').lower() == 'true':
        auto_fix_enabled = os.getenv('APPSEC_AUTO_FIX', 'false').lower() == 'true'
        auto_fix_mode = os.getenv('APPSEC_AUTO_FIX_MODE', '')

        if auto_fix_mode in ['1', '2', '3', '4']:
            # Adjust mode if needed findings aren't available
            if auto_fix_mode == '2' and not dependency_findings:
                choice = '1' if sast_findings else '4'
            elif auto_fix_mode == '3' and not dependency_findings:
                choice = '1' if sast_findings else '4'
            elif auto_fix_mode == '3' and not sast_findings:
                choice = '2' if dependency_findings else '4'
            else:
                choice = auto_fix_mode
        elif auto_fix_enabled:
            if sast_findings and dependency_findings:
                choice = '3'
            elif sast_findings:
                choice = '1'
            elif dependency_findings:
                choice = '2'
            else:
                choice = '4'
        else:
            choice = '4'

        env_type = "CI Environment" if is_github_actions() else "Web Interface"
        print(f"🤖 {env_type} detected - using auto-fix mode: {choice}")
        return choice

    # Interactive
    while True:
        choice = input("\nChoose auto-fix option [1-4]: ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print("Invalid choice. Please enter 1, 2, 3, or 4")


def _execute_remediation(
    repo_path: str,
    choice: str,
    sast_findings: list,
    dependency_findings: list,
    semgrep_count: int,
    secrets_count: int,
) -> dict:
    """Execute the chosen remediation option."""
    from auto_remediation.remediation import create_remediation_pr

    try:
        sast_success = dep_success = True

        if choice in ['1', '3'] and sast_findings:
            if semgrep_count > 0 and secrets_count > 0:
                print("🔧 Creating code security PR (SAST fixes + secret flagging)...")
            elif semgrep_count > 0:
                print("🔧 Creating SAST auto-fix PR...")
            else:
                print("🔧 Creating secrets detection PR (manual review required)...")
            sast_success = create_remediation_pr(repo_path, sast_findings, "sast")

        if choice in ['2', '3'] and dependency_findings:
            print("🔧 Creating dependency auto-fix PR...")
            dep_success = create_remediation_pr(repo_path, dependency_findings, "dependencies")

        if sast_success and dep_success:
            print("\n✅ Auto-remediation complete!")
            return {"success": True, "message": "Auto-remediation completed successfully"}
        else:
            print("\n⚠️ Auto-remediation completed with issues (check errors above)")
            return {"success": False, "message": "Auto-remediation had issues - check logs"}

    except Exception as e:
        print(f"\n❌ Auto-remediation failed: {e}")
        return {"success": False, "message": f"Auto-remediation failed: {e}"}


# ---------------------------------------------------------------------------
# Mode runners
# ---------------------------------------------------------------------------

async def run_auto_mode_async() -> list[dict[str, Any]]:
    """Run scanner in automatic mode (GitHub Actions). Single async entry point."""
    try:
        validate_environment_config()
    except Exception as e:
        logger.error(f"Environment configuration validation failed: {e}")
        return []

    # Determine repo path
    if is_github_actions():
        workspace = os.getenv('GITHUB_WORKSPACE', '')
        current_dir = os.getcwd()
        if workspace and workspace != current_dir and Path(workspace).exists():
            repo_path = validate_repo_path(workspace)
            print(f"🔧 Running as GitHub Action - scanning external repo: {workspace}")
        else:
            repo_path = validate_repo_path(current_dir)
            print(f"🔧 Running from copied files - scanning current directory: {current_dir}")
    else:
        repo_path = validate_repo_path(os.getcwd())

    # Set up output
    output_path = get_output_path(str(repo_path), BASE_OUTPUT_DIR)
    cleanup_old_scans(output_path)
    output_dirs = setup_output_directories(output_path)
    output_dir = output_dirs['base']

    scanners_to_run = ["semgrep", "gitleaks", "trivy"]
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')

    print("🔒 AppSec-Sentinel - Auto Mode")
    print(f"📁 Scanning: {repo_path}")
    print(f"📁 Output: {output_dir}")
    print(f"🔍 Scan level: {scan_level}")

    # Run full pipeline (single async call - no nested asyncio.run)
    all_findings, enhanced_findings = await run_full_scan_pipeline(
        str(repo_path), scanners_to_run, output_dir, scan_level,
    )

    if all_findings:
        handle_auto_remediation(str(repo_path), enhanced_findings)
    else:
        print("🎉 No security issues found!")

    return enhanced_findings


async def run_interactive_scan_async(repo_path: str) -> None:
    """Execute interactive security scan. Single async entry point."""
    # Set up output
    output_path = get_output_path(repo_path, BASE_OUTPUT_DIR)
    cleanup_old_scans(output_path)
    output_dirs = setup_output_directories(output_path)
    output_dir = output_dirs['base']

    print(f"📁 Output directory: {output_dir}")

    # Get user selections
    selected_tools = select_tools()
    scan_level = select_scan_level()

    scanners_to_run = [t for t in ['semgrep', 'gitleaks', 'trivy'] if t in selected_tools]
    run_code_quality = 'code_quality' in selected_tools
    run_sbom = 'sbom' in selected_tools

    # Temporarily override code quality setting
    original_code_quality = os.getenv('APPSEC_CODE_QUALITY')
    try:
        os.environ['APPSEC_CODE_QUALITY'] = 'true' if run_code_quality else 'false'

        print(f"\n🔍 Running security scan (level: {scan_level})...")
        all_findings, enhanced_findings = await run_full_scan_pipeline(
            repo_path, scanners_to_run, output_dir, scan_level, run_sbom_flag=run_sbom,
        )
    finally:
        if original_code_quality is not None:
            os.environ['APPSEC_CODE_QUALITY'] = original_code_quality
        else:
            os.environ.pop('APPSEC_CODE_QUALITY', None)

    # Auto-remediation
    handle_auto_remediation(repo_path, enhanced_findings)


# ---------------------------------------------------------------------------
# Usage tracking
# ---------------------------------------------------------------------------

def track_usage() -> None:
    """Track usage analytics locally for IP monitoring."""
    try:
        import platform
        import getpass
        from datetime import datetime, timezone

        usage_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.3.0',
            'mode': 'CI/CD' if is_github_actions() else 'CLI',
            'platform': platform.system(),
            'user_id': getpass.getuser()[:8] + "***",
            'scan_level': os.getenv('APPSEC_SCAN_LEVEL', 'critical-high'),
            'auto_fix_enabled': os.getenv('APPSEC_AUTO_FIX', 'false') == 'true',
        }

        logger.info(f"Usage Analytics: {json.dumps(usage_data)}")

        usage_log_dir = Path("outputs/analytics")
        usage_log_dir.mkdir(parents=True, exist_ok=True)
        usage_file = usage_log_dir / f"usage_{datetime.now().strftime('%Y%m%d')}.json"

        existing_logs = []
        if usage_file.exists():
            try:
                with open(usage_file, 'r') as f:
                    existing_logs = json.load(f)
            except Exception:
                existing_logs = []

        existing_logs.append(usage_data)
        with open(usage_file, 'w') as f:
            json.dump(existing_logs, f, indent=2)

    except Exception as e:
        logger.debug(f"Usage tracking failed (non-critical): {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point - single asyncio.run() for the entire session."""
    track_usage()

    if os.getenv('APPSEC_DEBUG', 'false').lower() == 'true':
        set_debug_mode(True)
        logger.debug("AppSec-Sentinel starting in debug mode")

    env_type = "CI/CD" if is_github_actions() else "CLI"
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
    logger.info(f"Starting AppSec-Sentinel - Mode: {env_type}, Scan Level: {scan_level}")

    # CI/CD auto mode
    if is_github_actions():
        asyncio.run(run_auto_mode_async())
        return

    # Interactive mode
    print("\n" + "=" * 80)
    print("🔒 AppSec-Sentinel - Open Source Security Scanner")
    print("=" * 80)
    print("Comprehensive security scanner with cross-file analysis and optional LLM-powered fixes")
    print("=" * 80)
    print()

    try:
        choice = show_interactive_menu()
        if choice == 'q':
            print("👋 Goodbye!")
            return

        if choice == '1':
            repo_path = select_repository()
            if not repo_path:
                return
            asyncio.run(run_interactive_scan_async(repo_path))

    except KeyboardInterrupt:
        print("\n\n👋 Scan cancelled by user")
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()
