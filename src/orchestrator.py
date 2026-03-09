"""
Scan orchestration for AppSec-Sentinel.

Coordinates parallel scanner execution, report generation, SBOM creation,
and cross-file analysis. All async work flows through this module so
there's a single event loop entry point.
"""

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from logging_config import get_logger
from scanners.validation import detect_languages

# Scanner imports
from scanners.semgrep import run_semgrep
from scanners.gitleaks import run_gitleaks
from scanners.trivy import run_trivy_scan

# Code quality scanner imports
from scanners.eslint import run_eslint
from scanners.pylint import run_pylint
from scanners.checkstyle import run_checkstyle
from scanners.golangci_lint import run_golangci_lint
from scanners.rubocop import run_rubocop
from scanners.clippy import run_clippy
from scanners.phpstan import run_phpstan

# Optional modules (these have external deps that may not be installed)
try:
    from enhanced_analyzer import enhance_findings_with_cross_file, generate_cross_file_enhanced_report
    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False

try:
    from sbom_generator import generate_repository_sbom
    SBOM_AVAILABLE = True
except ImportError:
    SBOM_AVAILABLE = False

from reporting.html import generate_html_report

logger = get_logger(__name__)


def run_security_scans(
    repo_path: str,
    scanners_to_run: list[str],
    output_dir: Path,
    scan_level: str | None = None,
) -> list[dict[str, Any]]:
    """
    Synchronous wrapper — runs the async scanner pipeline.
    Only call this from non-async code (e.g. main entry point).
    """
    if scan_level is None:
        scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
    return asyncio.run(_run_scans_async(repo_path, scanners_to_run, output_dir, scan_level))


async def _run_scans_async(
    repo_path: str,
    scanners_to_run: list[str],
    output_dir: Path,
    scan_level: str = 'critical-high',
) -> list[dict[str, Any]]:
    """Run security scanners and code quality linters in parallel via thread pool."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw").mkdir(parents=True, exist_ok=True)

    logger.info(f"Scan pipeline starting - scan_level: {scan_level}")

    # Detect languages for code quality scanning
    enable_code_quality = os.getenv('APPSEC_CODE_QUALITY', 'true').lower() == 'true'
    detected_languages: dict[str, int] = {}
    if enable_code_quality:
        try:
            detected_languages = detect_languages(Path(repo_path))
            if detected_languages:
                logger.info(f"Detected languages: {', '.join(sorted(detected_languages))}")
        except Exception as e:
            logger.warning(f"Language detection failed: {e}")

    # Build scanner task list
    scanner_tasks = _build_scanner_tasks(
        repo_path, output_dir, scan_level, scanners_to_run,
        enable_code_quality, detected_languages,
    )

    if not scanner_tasks:
        print("No scanners selected")
        return []

    security_count = sum(1 for t in scanner_tasks if t['category'] == 'security')
    quality_count = sum(1 for t in scanner_tasks if t['category'] == 'code_quality')
    print(f"🔍 Starting scan ({security_count} security + {quality_count} code quality scanners)...")
    start_time = time.time()

    # Run all scanners concurrently in thread pool
    results = await asyncio.gather(*[
        asyncio.to_thread(task['func']) for task in scanner_tasks
    ], return_exceptions=True)

    # Collect findings
    all_findings: list[dict] = []
    security_findings_count = 0
    code_quality_findings_count = 0

    for i, result in enumerate(results):
        task = scanner_tasks[i]
        if isinstance(result, Exception):
            print(f"❌ {task['display_name']} failed: {result}")
        else:
            findings = result if result else []
            for finding in findings:
                finding['tool'] = task['name']
            all_findings.extend(findings)

            if task['category'] == 'code_quality':
                code_quality_findings_count += len(findings)
                if findings:
                    print(f"✅ {task['display_name']}: {len(findings)} code quality issues")
                elif not isinstance(result, Exception):
                    print(f"✅ {task['display_name']}: clean (no issues found)")
            else:
                security_findings_count += len(findings)
                if findings:
                    print(f"✅ {task['display_name']}: {len(findings)} vulnerabilities")
                else:
                    print(f"✅ {task['display_name']}: no issues")

    elapsed = time.time() - start_time
    if code_quality_findings_count > 0:
        print(f"🎯 Scan complete: {security_findings_count} security issues + {code_quality_findings_count} code quality issues in {elapsed:.1f}s")
    else:
        print(f"🎯 Scan complete: {security_findings_count} vulnerabilities found in {elapsed:.1f}s")

    return all_findings


def _build_scanner_tasks(
    repo_path: str,
    output_dir: Path,
    scan_level: str,
    scanners_to_run: list[str],
    enable_code_quality: bool,
    detected_languages: dict[str, int],
) -> list[dict]:
    """Build the list of scanner task descriptors."""
    raw_dir = str(output_dir / "raw")
    tasks: list[dict] = []

    # Security scanners
    if "semgrep" in scanners_to_run or "all" in scanners_to_run:
        tasks.append({
            'name': 'semgrep',
            'display_name': 'Semgrep (SAST)',
            'func': lambda sl=scan_level: run_semgrep(repo_path, raw_dir, sl),
            'category': 'security',
        })
    if "gitleaks" in scanners_to_run or "all" in scanners_to_run:
        tasks.append({
            'name': 'gitleaks',
            'display_name': 'Gitleaks (Secrets)',
            'func': lambda: run_gitleaks(repo_path, raw_dir),
            'category': 'security',
        })
    if "trivy" in scanners_to_run or "all" in scanners_to_run:
        tasks.append({
            'name': 'trivy',
            'display_name': 'Trivy (Dependencies)',
            'func': lambda: run_trivy_scan(repo_path, raw_dir),
            'category': 'security',
        })

    # Code quality linters (based on detected languages)
    if not enable_code_quality or not detected_languages:
        return tasks

    quality_scanners = [
        ({'javascript', 'typescript'}, 'eslint', 'ESLint', run_eslint),
        ({'python'}, 'pylint', 'Pylint', run_pylint),
        ({'java'}, 'checkstyle', 'Checkstyle', run_checkstyle),
        ({'go'}, 'golangci-lint', 'golangci-lint', run_golangci_lint),
        ({'ruby'}, 'rubocop', 'RuboCop', run_rubocop),
        ({'rust'}, 'clippy', 'Clippy', run_clippy),
        ({'php'}, 'phpstan', 'PHPStan', run_phpstan),
    ]

    for langs, name, display, func in quality_scanners:
        if langs & detected_languages.keys():
            tasks.append({
                'name': name,
                'display_name': f'{display} (Code Quality)',
                'func': lambda f=func: f(repo_path, raw_dir),
                'category': 'code_quality',
            })
            logger.debug(f"Added {display} to scan pipeline")

    return tasks


def _build_summary(findings: list[dict], context_summary: str = "") -> str:
    """Build the AI summary string for reports."""
    if not findings:
        return "🎉 Security scan completed successfully with no critical or high-severity issues found."

    security_findings = [f for f in findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
    code_quality_findings = [f for f in findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

    stats = {
        'total_security': len(security_findings),
        'total_code_quality': len(code_quality_findings),
        'critical': len([f for f in security_findings if f.get('severity', '').lower() == 'critical']),
        'high': len([f for f in security_findings if f.get('severity', '').lower() in ['high', 'error']]),
        'sast': len([f for f in security_findings if f.get('tool') == 'semgrep']),
        'secrets': len([f for f in security_findings if f.get('tool') == 'gitleaks']),
        'deps': len([f for f in security_findings if f.get('tool') == 'trivy']),
    }

    risk = '🔴 High Risk' if stats['critical'] > 0 else '🟡 Medium Risk' if stats['high'] > 0 else '🟢 Low Risk'

    security_breakdown = f"""**Security Issues ({stats['total_security']} total):**
• {stats['critical']} critical vulnerabilities requiring immediate attention
• {stats['high']} high-severity issues needing prompt remediation
• {stats['sast']} code security issues (SAST)
• {stats['secrets']} secrets detected in repository
• {stats['deps']} vulnerable dependencies identified"""

    code_quality_section = ""
    if stats['total_code_quality'] > 0:
        code_quality_section = f"""

**Code Quality Issues ({stats['total_code_quality']} total):**
• Maintainability, complexity, and best practice violations
• Always shown regardless of security scan level"""

    return f"""🛡️ Security Analysis Complete

**Risk Assessment:** {risk}

{security_breakdown}{code_quality_section}{context_summary}

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""


async def enhance_and_report(
    findings: list[dict],
    repo_path: str,
    output_dir: Path,
) -> list[dict]:
    """
    Enhance findings with cross-file analysis and generate all reports.
    Runs within an existing event loop (no nested asyncio.run).
    """
    enhanced = findings

    # Cross-file enhancement
    if CROSS_FILE_AVAILABLE and findings:
        print("🧠 Running cross-file enhancement analysis...")
        try:
            enhanced = await enhance_findings_with_cross_file(findings, repo_path)
            print(f"✅ Enhanced {len(enhanced)} findings with cross-file analysis")
        except Exception as e:
            logger.warning(f"Cross-file enhancement failed, using standard analysis: {e}")
            enhanced = findings

    # HTML report
    ai_summary = _build_summary(enhanced)
    try:
        generate_html_report(
            enhanced, ai_summary, str(output_dir),
            repo_path, detect_languages(Path(repo_path)),
        )
        print(f"📄 HTML report: {output_dir / 'report.html'}")
    except Exception as e:
        print(f"⚠️  HTML report generation failed: {e}")
        logger.error(f"HTML report error: {e}", exc_info=True)

    # Cross-file PR summary
    if CROSS_FILE_AVAILABLE and enhanced:
        try:
            report = await generate_cross_file_enhanced_report(enhanced, repo_path)
            pr_path = output_dir / "pr-findings.txt"
            with open(pr_path, 'w') as f:
                f.write(report.get('pr_summary', 'No PR summary available'))
            print(f"📄 Cross-file enhanced PR summary: {pr_path}")
        except Exception as e:
            logger.warning(f"Cross-file report generation failed: {e}")

    return enhanced


async def generate_sbom(repo_path: str, output_dir: Path) -> None:
    """Generate SBOM if Syft is available."""
    if not SBOM_AVAILABLE:
        print("⚠️ SBOM generation requires Syft (scan continues without SBOM)")
        return
    print("📋 Generating SBOM for compliance...")
    try:
        await generate_repository_sbom(repo_path, str(output_dir / "sbom"))
        print("✅ SBOM generated in outputs/sbom/")
    except Exception as e:
        logger.warning(f"SBOM generation failed: {e}")
        print("⚠️ SBOM generation failed (scan continues)")


async def run_full_scan_pipeline(
    repo_path: str,
    scanners_to_run: list[str],
    output_dir: Path,
    scan_level: str,
    run_sbom_flag: bool = True,
) -> tuple[list[dict], list[dict]]:
    """
    Complete scan pipeline: scan -> enhance -> report -> SBOM.

    This is the single async entry point. Call via asyncio.run() once.

    Returns:
        (all_findings, enhanced_findings)
    """
    # Run scanners
    all_findings = await _run_scans_async(repo_path, scanners_to_run, output_dir, scan_level)

    # Enhance and generate reports
    enhanced = all_findings
    if all_findings:
        print(f"\n📊 Found {len(all_findings)} findings")
        enhanced = await enhance_and_report(all_findings, repo_path, output_dir)

    # SBOM
    if run_sbom_flag:
        await generate_sbom(repo_path, output_dir)

    return all_findings, enhanced
