#!/usr/bin/env python3
"""
SCA (Software Composition Analysis) Scanner

This module integrates Trivy for dependency scanning.
It can use pre-existing Trivy results from GitHub Actions or run Trivy locally.
"""

import subprocess
import json
import os
from pathlib import Path
import logging
from typing import List, Dict, Any
import shlex

# Import configuration constants  
from config import format_subprocess_error
from .validation import validate_binary_path, validate_repo_path

logger = logging.getLogger(__name__)

def run_trivy_scan(repo_path: str, output_dir: Path = None) -> List[Dict[str, Any]]:
    """
    Run Trivy SCA (Software Composition Analysis) scanner on the given repository.
    First checks for existing Trivy results from GitHub Actions, then runs locally if needed.
    Returns a list of findings in standardized format.
    """
    try:
        # Use provided output_dir or default
        if output_dir is None:
            from config import BASE_OUTPUT_DIR
            out_dir = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            out_dir = Path(output_dir)

        out_dir.mkdir(parents=True, exist_ok=True)
        output_file = out_dir / "trivy-sca.json"

        # Run Trivy locally
        logger.debug("Running Trivy scan locally")
        if not _run_trivy_scan(repo_path, output_file):
            return []

        # Parse and return findings from the JSON output
        return _parse_trivy_results(output_file, repo_path)
            
    except Exception as e:
        logger.error(f"Error in SCA scan: {e}")
        return []

def _run_trivy_scan(repo_path: str, output_file: Path) -> bool:
    """Run Trivy scan locally and return True if successful."""
    try:
        # Validate and sanitize repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            return False
        
        # Check what dependency files exist to provide better feedback
        dep_files = []
        dep_patterns = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle"
        ]
        
        for pattern in dep_patterns:
            matches = list(repo_path_obj.rglob(pattern))
            dep_files.extend(matches)
        
        if dep_files:
            logger.debug(f"Found dependency files: {[f.name for f in dep_files[:5]]}")
        else:
            logger.debug("No common dependency files found - scanning filesystem anyway")
        
        # Get and validate Trivy binary path
        trivy_bin = validate_binary_path('TRIVY_BIN', 'trivy')
        if not trivy_bin:
            logger.error("Could not validate trivy binary")
            return False
        
        # Delete old output file BEFORE running to prevent loading stale results
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old trivy output file: {output_file}")

        # Run Trivy filesystem scan for vulnerabilities (CRITICAL and HIGH only)
        # Enable all scanners to detect Gradle/Maven dependencies
        cmd = [
            trivy_bin, "fs",
            "--format", "json",
            "--output", str(output_file),
            "--severity", "CRITICAL,HIGH",
            "--scanners", "vuln",
            "--list-all-pkgs",  # List all packages even without lockfiles
            "--quiet",
            str(repo_path_obj)
        ]

        logger.debug(f"Running Trivy SCA scan on {repo_path_obj}")
        # Use subprocess.run with shell=False for security
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False)
        
        if result.returncode != 0:
            # Trivy may return non-zero even on successful scans with findings
            # Only treat as error if no output file was created
            if not output_file.exists():
                error_details = format_subprocess_error('trivy', result.returncode, result.stderr, result.stdout)
                logger.error(error_details)
                return False
            else:
                logger.info(f"Trivy returned code {result.returncode} but created output file - continuing")
        
        return True
        
    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('trivy', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return False
    except FileNotFoundError:
        not_found_msg = format_subprocess_error('trivy', 127, "Trivy command not found in PATH")
        logger.error(not_found_msg)
        return False
    except Exception as e:
        logger.error(f"Error running Trivy scan: {e}")
        return False

def _parse_trivy_results(output_file: Path, repo_path: str) -> List[Dict[str, Any]]:
    """Parse Trivy JSON results and return standardized findings."""
    try:
        if not output_file.exists():
            logger.info("Trivy found no vulnerabilities (no output file)")
            return []

        # Check for dependency files to provide context
        repo_path_obj = Path(repo_path)
        dep_patterns = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle"
        ]
        dep_files = []
        for pattern in dep_patterns:
            matches = list(repo_path_obj.rglob(pattern))
            dep_files.extend(matches)

        with open(output_file, encoding='utf-8') as f:
            data = json.load(f)
            
        # Transform Trivy output to standardized format
        standardized_findings = []
        results = data.get("Results", [])
        
        # Count what was scanned
        scanned_targets = len(results)
        total_vulnerabilities = 0
        
        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                finding = {
                    "path": target,
                    "line": 1,  # Dependencies don't have specific lines
                    "description": f"{vuln.get('PkgName', 'Unknown')} {vuln.get('InstalledVersion', '')}: {vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown vulnerability'))}",
                    "severity": vuln.get("Severity", "UNKNOWN").lower(),
                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "references": vuln.get("References", []),
                    "tool": "trivy",
                    "category": "security"  # Trivy scans dependencies = security only
                }
                standardized_findings.append(finding)
        
        if scanned_targets > 0 and total_vulnerabilities == 0:
            logger.info(f"Trivy scanned {scanned_targets} dependency files - no vulnerabilities found (dependencies are clean)")
        elif total_vulnerabilities > 0:
            logger.info(f"Trivy found {len(standardized_findings)} dependency vulnerabilities across {scanned_targets} files")
        else:
            logger.info("Trivy found no dependency files to scan")
            # Check if this is a Gradle/Maven project without lockfiles
            if dep_files:
                gradle_files = [f for f in dep_files if 'gradle' in str(f).lower()]
                maven_files = [f for f in dep_files if 'pom.xml' in str(f).lower()]
                if gradle_files or maven_files:
                    logger.warning("⚠️  Gradle/Maven project detected but no lockfiles found")
                    logger.warning("    → Trivy requires lockfiles or built artifacts to scan Java dependencies")
                    logger.warning("    → Run 'gradle dependencies --write-locks' or build the project first")
                    logger.warning("    → Alternatively, scan the built JAR: trivy image your-app.jar")
            
        return standardized_findings
        
    except Exception as e:
        logger.error(f"Error parsing Trivy results: {e}")
        return []
