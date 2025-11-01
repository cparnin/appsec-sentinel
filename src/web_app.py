#!/usr/bin/env python3
"""
AppSec AI Scanner - Web Interface

🔒 Web wrapper for the AppSec AI Scanner that preserves all existing functionality.

This creates web endpoints that call the exact same functions as the CLI version,
ensuring identical behavior and maintaining all security features.

Usage:
    python web_app.py              # Start web server
    curl -X POST /scan             # API endpoint
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, send_file, abort, render_template
from flask_cors import CORS
import tempfile
import shutil
import logging

# Add src directory to path so we can import existing modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import ALL existing functionality (no changes to existing code)
from main import (
    validate_repo_path,
    validate_environment_config,
    run_security_scans,
    handle_auto_remediation,
    track_usage
)
from reporting.html import generate_html_report

# Import path utilities for multi-repo/branch output structure
from path_utils import (
    get_output_path, cleanup_old_scans, setup_output_directories
)
from config import BASE_OUTPUT_DIR

# Configure logging for web app
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app with template directory
app = Flask(__name__, template_folder='templates')
CORS(app)  # Enable CORS for web UI integration

# Global config (same as CLI)
WEB_CONFIG = None
LAST_SCAN_OUTPUT_DIR = None  # Track most recent scan output directory

def init_web_config():
    """Initialize configuration using existing validation function."""
    global WEB_CONFIG
    if WEB_CONFIG is None:
        WEB_CONFIG = validate_environment_config()
    return WEB_CONFIG

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'AppSec AI Scanner Web API',
        'version': '1.0.0'
    })

@app.route('/config', methods=['GET'])
def get_config():
    """Get current scanner configuration."""
    try:
        config = init_web_config()
        # Return safe config info (no API keys)
        safe_config = {
            'ai_provider': config.get('ai_provider'),
            'scan_level': config.get('scan_level'),
            'auto_fix_enabled': config.get('auto_fix', False),
            'scanners_available': ['semgrep', 'gitleaks', 'trivy']
        }
        return jsonify(safe_config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan_repository():
    """
    Main scanning endpoint that calls existing CLI functions.

    Request body:
    {
        "repo_path": "/path/to/repository",
        "scan_level": "critical-high" | "all" (optional),
        "auto_fix": true | false (optional),
        "selected_tools": ["semgrep", "gitleaks", "trivy", "code_quality", "sbom"] (optional)
    }
    """
    try:
        # Parse request
        data = request.get_json()
        if not data or 'repo_path' not in data:
            return jsonify({'error': 'repo_path is required'}), 400
            
        repo_path = data['repo_path']
        scan_level = data.get('scan_level', 'critical-high')
        auto_fix = data.get('auto_fix', False)
        selected_tools = data.get('selected_tools', ['semgrep', 'gitleaks', 'trivy', 'code_quality', 'sbom'])

        # Parse tool selection
        run_code_quality = 'code_quality' in selected_tools
        run_sbom = 'sbom' in selected_tools

        # Extract security scanners only
        scanners_to_run = [tool for tool in selected_tools if tool in ['semgrep', 'gitleaks', 'trivy']]

        # Ensure at least one scanner is selected
        if not scanners_to_run:
            return jsonify({'error': 'At least one security scanner must be selected'}), 400

        # Validate repository path using existing function
        try:
            validated_path = validate_repo_path(repo_path)
        except (ValueError, PermissionError) as e:
            return jsonify({'error': f'Invalid repository path: {str(e)}'}), 400
            
        # Set environment variables for this scan
        original_scan_level = os.environ.get('APPSEC_SCAN_LEVEL')
        original_auto_fix = os.environ.get('APPSEC_AUTO_FIX')
        original_code_quality = os.environ.get('APPSEC_CODE_QUALITY')

        logger.info(f"🔍 Web scan request - scan_level: {scan_level}, tools: {selected_tools}")
        os.environ['APPSEC_SCAN_LEVEL'] = scan_level
        os.environ['APPSEC_AUTO_FIX'] = str(auto_fix).lower()
        os.environ['APPSEC_CODE_QUALITY'] = 'true' if run_code_quality else 'false'
        logger.info(f"🔍 Web scan - configured APPSEC_SCAN_LEVEL={scan_level}, APPSEC_CODE_QUALITY={run_code_quality}")

        try:
            # Track usage for IP monitoring
            track_usage()

            # Initialize config
            config = init_web_config()

            # Set up output directory with new repo/branch structure
            output_path = get_output_path(str(validated_path), BASE_OUTPUT_DIR)

            # Clean up old scans (keep only most recent)
            cleanup_old_scans(output_path)

            # Set up directory structure
            output_dirs = setup_output_directories(output_path)
            output_dir = output_dirs['base']

            # Track output dir for report serving
            global LAST_SCAN_OUTPUT_DIR
            LAST_SCAN_OUTPUT_DIR = output_dir

            # Run scanning logic
            print(f"🔍 Starting scan of {validated_path}")
            print(f"🔧 Running scanners: {', '.join(scanners_to_run)}")

            # Use existing scanning function with selected scanners
            all_findings = run_security_scans(str(validated_path), scanners_to_run, output_dir, scan_level)
            
            # Add cross-file analysis enhancement like CLI mode does
            enhanced_findings = all_findings
            try:
                from enhanced_analyzer import enhance_findings_with_cross_file
                if all_findings:
                    print("🧠 Running cross-file enhancement analysis...")
                    enhanced_findings = asyncio.run(enhance_findings_with_cross_file(all_findings, str(validated_path)))
                    print(f"✅ Cross-file enhanced {len(enhanced_findings)} findings with context analysis")
            except ImportError:
                print("⚠️ Cross-file analysis integration not available")
            except Exception as e:
                print(f"⚠️ Cross-file enhancement failed: {e}")
                enhanced_findings = all_findings
            
            # Generate reports using existing functions
            html_report_path = None
            if enhanced_findings:
                # Separate security from code quality findings
                security_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
                code_quality_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

                summary_stats = {
                    'total_security': len(security_findings),
                    'total_code_quality': len(code_quality_findings),
                    'critical': len([f for f in security_findings if f.get('severity', '').lower() == 'critical']),
                    'high': len([f for f in security_findings if f.get('severity', '').lower() in ['high', 'error']]),
                    'sast': len([f for f in security_findings if f.get('tool') == 'semgrep']),
                    'secrets': len([f for f in security_findings if f.get('tool') == 'gitleaks']),
                    'deps': len([f for f in security_findings if f.get('tool') == 'trivy'])
                }

                # Build security findings section
                security_breakdown = f"""**Security Issues ({summary_stats['total_security']} total):**
• {summary_stats['critical']} critical vulnerabilities requiring immediate attention
• {summary_stats['high']} high-severity issues needing prompt remediation
• {summary_stats['sast']} code security issues (SAST)
• {summary_stats['secrets']} secrets detected in repository
• {summary_stats['deps']} vulnerable dependencies identified"""

                # Add code quality section if present
                code_quality_section = ""
                if summary_stats['total_code_quality'] > 0:
                    code_quality_section = f"""

**Code Quality Issues ({summary_stats['total_code_quality']} total):**
• Maintainability, complexity, and best practice violations
• Always shown regardless of security scan level"""

                ai_summary = f"""🛡️ Security Analysis Complete

**Risk Assessment:** {'🔴 High Risk' if summary_stats['critical'] > 0 else '🟡 Medium Risk' if summary_stats['high'] > 0 else '🟢 Low Risk'}

{security_breakdown}{code_quality_section}

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""

                html_report_path = generate_html_report(enhanced_findings, ai_summary, str(output_dir), str(validated_path))
                
                # Generate PR summary like CLI does
                try:
                    pr_summary_path = output_dir / "pr-findings.txt"
                    with open(pr_summary_path, 'w') as f:
                        f.write(f"Security Scan Results for {validated_path.name}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(ai_summary)
                        if len(enhanced_findings) > 0:
                            f.write("\n\nDetailed Findings:\n")
                            for i, finding in enumerate(enhanced_findings[:10], 1):  # Limit to top 10
                                f.write(f"{i}. {finding.get('extra', {}).get('message', 'Security issue')} ")
                                f.write(f"({finding.get('severity', 'unknown')} - {finding.get('tool', 'scanner')})\n")
                except Exception as e:
                    logger.warning(f"Could not generate PR summary: {e}")
            else:
                ai_summary = "🎉 Security scan completed successfully with no critical or high-severity issues found."
                html_report_path = generate_html_report([], ai_summary, str(output_dir), str(validated_path))
            
            # Generate SBOM if user selected it
            if run_sbom:
                try:
                    from sbom_generator import generate_repository_sbom
                    print("🔧 Generating SBOM...")
                    sbom_result = asyncio.run(generate_repository_sbom(str(validated_path), str(output_dir / "sbom")))
                    print("✅ SBOM generated successfully")
                    logger.info(f"SBOM generation results: {sbom_result}")
                except ImportError as e:
                    logger.error(f"SBOM generator module not found: {e}")
                except Exception as e:
                    logger.error(f"SBOM generation failed: {e}")
                    # Continue with scan even if SBOM fails
            
            # Handle auto-remediation non-interactively 
            remediation_results = None
            if auto_fix and all_findings:
                # Get auto_fix_mode from request data (sent from frontend form)
                auto_fix_mode = data.get('auto_fix_mode', '3')  # Default to both if not specified
                
                # Set environment variables for non-interactive mode
                os.environ['APPSEC_WEB_MODE'] = 'true'
                os.environ['APPSEC_AUTO_FIX_MODE'] = str(auto_fix_mode)
                try:
                    print(f"🔧 Starting auto-remediation...")
                    remediation_results = handle_auto_remediation(str(validated_path), all_findings)
                    if remediation_results.get("success"):
                        print("✅ Auto-remediation completed")
                    else:
                        print(f"⚠️ Auto-remediation had issues: {remediation_results.get('message', 'Unknown error')}")
                except Exception as e:
                    logger.error(f"Auto-remediation failed: {e}")
                    remediation_results = {"success": False, "message": f"Auto-remediation failed: {str(e)}"}
                    print(f"❌ Auto-remediation failed: {e}")
                finally:
                    # Clean up environment variables
                    if 'APPSEC_WEB_MODE' in os.environ:
                        del os.environ['APPSEC_WEB_MODE']
                    if 'APPSEC_AUTO_FIX_MODE' in os.environ:
                        del os.environ['APPSEC_AUTO_FIX_MODE']
            
            # Prepare response
            response = {
                'success': True,
                'scan_summary': {
                    'total_findings': len(all_findings),
                    'critical_findings': len([f for f in all_findings if f.get('severity') == 'critical']),
                    'high_findings': len([f for f in all_findings if f.get('severity') == 'high']),
                    'repository_path': str(validated_path),
                    'scan_level': scan_level,
                    'auto_fix_enabled': auto_fix
                },
                'findings': all_findings,
                'html_report_available': html_report_path is not None,
                'remediation_applied': remediation_results is not None
            }
            
            if remediation_results:
                response['remediation_summary'] = remediation_results
                
            logger.info(f"✅ Web scan completed: {len(all_findings)} findings")
            return jsonify(response)
            
        finally:
            # Restore original environment variables
            if original_scan_level:
                os.environ['APPSEC_SCAN_LEVEL'] = original_scan_level
            elif 'APPSEC_SCAN_LEVEL' in os.environ:
                del os.environ['APPSEC_SCAN_LEVEL']

            if original_auto_fix:
                os.environ['APPSEC_AUTO_FIX'] = original_auto_fix
            elif 'APPSEC_AUTO_FIX' in os.environ:
                del os.environ['APPSEC_AUTO_FIX']

            if original_code_quality:
                os.environ['APPSEC_CODE_QUALITY'] = original_code_quality
            elif 'APPSEC_CODE_QUALITY' in os.environ:
                del os.environ['APPSEC_CODE_QUALITY']
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/threat-model', methods=['POST'])
def generate_threat_model():
    """
    Generate threat model using STRIDE framework.

    Request body:
    {
        "repo_path": "/path/to/repository"
    }
    """
    try:
        # Parse request
        data = request.get_json()
        if not data or 'repo_path' not in data:
            return jsonify({'error': 'repo_path is required'}), 400

        repo_path = data['repo_path']

        # Validate repository path
        try:
            validated_path = validate_repo_path(repo_path)
        except (ValueError, PermissionError) as e:
            return jsonify({'error': f'Invalid repository path: {str(e)}'}), 400

        # Track usage
        track_usage()

        # Set up output directory with repo/branch structure
        output_path = get_output_path(str(validated_path), BASE_OUTPUT_DIR)
        output_dirs = setup_output_directories(output_path)
        output_dir = output_dirs['base']

        logger.info(f"🛡️  Generating threat model for {validated_path}")

        # Load existing scan findings if available
        findings = []
        raw_dir = output_dir / "raw"
        if raw_dir.exists():
            logger.info("📊 Loading existing scan results for enhanced analysis")
            for json_file in raw_dir.glob("*.json"):
                try:
                    with open(json_file) as f:
                        data_content = json.load(f)
                        if isinstance(data_content, dict) and 'results' in data_content:
                            findings.extend(data_content['results'])
                        elif isinstance(data_content, list):
                            findings.extend(data_content)
                except Exception as e:
                    logger.debug(f"Could not load {json_file}: {e}")

        # Import and run threat analyzer
        from threat_modeling import ThreatAnalyzer

        analyzer = ThreatAnalyzer(str(validated_path))
        threat_model = analyzer.analyze(findings)

        # Export threat model files
        exported_files = analyzer.export_threat_model(threat_model, str(output_dir))

        # Track output dir for report serving
        global LAST_SCAN_OUTPUT_DIR
        LAST_SCAN_OUTPUT_DIR = output_dir

        logger.info(f"✅ Threat model generated at {output_dir}")

        return jsonify({
            'success': True,
            'threat_model': threat_model,
            'files': {
                'json': str(exported_files['json']),
                'markdown': str(exported_files['markdown']),
                'diagram': str(exported_files['diagram'])
            },
            'summary': {
                'total_threats': threat_model['summary']['total_threats'],
                'attack_surface_score': threat_model['summary']['attack_surface_score'],
                'risk_level': threat_model['summary']['risk_level'],
                'stride_breakdown': threat_model['summary']['stride_breakdown']
            }
        }), 200

    except ImportError as e:
        logger.error(f"Threat modeling module not available: {e}")
        return jsonify({'error': 'Threat modeling module not available'}), 500
    except Exception as e:
        logger.error(f"Threat model generation error: {e}")
        return jsonify({'error': f'Threat model generation failed: {str(e)}'}), 500

@app.route('/report', methods=['GET'])
def get_html_report():
    """Serve the generated HTML report."""
    try:
        global LAST_SCAN_OUTPUT_DIR

        if LAST_SCAN_OUTPUT_DIR is None:
            return jsonify({'error': 'No scan has been run yet. Please run a scan first.'}), 404

        report_path = Path(LAST_SCAN_OUTPUT_DIR) / "report.html"
        if not report_path.exists():
            return jsonify({'error': 'No report available. Run a scan first.'}), 404

        response = send_file(report_path, as_attachment=False, mimetype='text/html')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports/<filename>', methods=['GET'])
def get_report_file(filename):
    """Serve specific report files (JSON, SBOM, etc.)."""
    try:
        global LAST_SCAN_OUTPUT_DIR

        if LAST_SCAN_OUTPUT_DIR is None:
            return jsonify({'error': 'No scan has been run yet. Please run a scan first.'}), 404

        # Security: Only allow specific file types
        allowed_files = {
            'semgrep.json', 'gitleaks.json', 'trivy-sca.json',
            'sbom.cyclonedx.json', 'sbom.spdx.json', 'pr-findings.txt'
        }

        if filename not in allowed_files:
            return jsonify({'error': 'File not allowed'}), 403

        output_dir = Path(LAST_SCAN_OUTPUT_DIR)

        if filename.endswith('.json') and not filename.startswith('sbom'):
            file_path = output_dir / "raw" / filename
        elif filename.startswith('sbom'):
            file_path = output_dir / "sbom" / filename
        else:
            file_path = output_dir / filename

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        response = send_file(file_path, as_attachment=True)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        logger.error(f"File error: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'API endpoint not found'}), 404

@app.route('/', methods=['GET'])
def index():
    """Main web interface for the scanner."""
    # Get repository info to display server-side
    logger.info("Loading index page, getting repository info...")
    try:
        current_dir_info = get_current_directory_info()
        logger.info(f"Repository info: {current_dir_info}")
        return render_template('index.html', 
                             repo_path=current_dir_info['path'],
                             repo_display_name=current_dir_info['display_name'])
    except Exception as e:
        logger.error(f"Error getting repo info for template: {e}")
        logger.error(f"Exception details: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return render_template('index.html', 
                             repo_path='/app/scan',
                             repo_display_name='mounted-repository')

def get_current_directory_info():
    """Helper function to get current directory info."""
    # In Docker container, use the standard mounted scan directory
    if os.path.exists('/app/scan'):
        # Get the actual repository name from the mounted directory
        try:
            # Try to get git repository name
            import subprocess
            result = subprocess.run(['git', 'rev-parse', '--show-toplevel'], 
                                  cwd='/app/scan', capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                repo_name = os.path.basename(result.stdout.strip())
            else:
                # Fallback to directory name
                repo_name = "mounted-repository"
                # Try to read some files to get a better name
                scan_dir = Path('/app/scan')
                if (scan_dir / 'package.json').exists():
                    import json
                    try:
                        with open(scan_dir / 'package.json') as f:
                            pkg = json.load(f)
                            repo_name = pkg.get('name', repo_name)
                            logger.info(f"Found package.json with name: {repo_name}")
                    except Exception as e:
                        logger.error(f"Error reading package.json: {e}")
                else:
                    logger.info(f"package.json not found at {scan_dir / 'package.json'}")
                    # List what files ARE there for debugging
                    try:
                        files = list(scan_dir.glob('*'))[:10]  # First 10 files
                        logger.info(f"Files in scan dir: {[f.name for f in files]}")
                    except Exception as e:
                        logger.error(f"Error listing scan dir: {e}")
                    
                    # Try other file types
                    if (scan_dir / 'pyproject.toml').exists() or (scan_dir / 'setup.py').exists():
                        repo_name = scan_dir.name if scan_dir.name != 'scan' else repo_name
        except Exception:
            repo_name = "mounted-repository"
            
        return {
            'path': '/app/scan',
            'display_name': repo_name
        }
    else:
        # Fallback to actual current directory for local development
        current_dir = Path(os.getcwd())
        repo_path = current_dir
        repo_name = current_dir.name

        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                cwd=current_dir,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                repo_path = Path(result.stdout.strip())
                repo_name = repo_path.name
        except Exception:
            pass

        return {
            'path': str(repo_path),
            'display_name': repo_name
        }

@app.route('/current-directory', methods=['GET'])
def get_current_directory():
    """Get the current working directory."""
    try:
        # In Docker container, use the standard mounted scan directory
        if os.path.exists('/app/scan'):
            # Get the actual repository name from the mounted directory
            try:
                # Try package.json FIRST (more reliable than git for mounted repos)
                scan_dir = Path('/app/scan')
                repo_name = "mounted-repository"
                
                if (scan_dir / 'package.json').exists():
                    import json
                    with open(scan_dir / 'package.json') as f:
                        pkg = json.load(f)
                        repo_name = pkg.get('name', repo_name)
                elif (scan_dir / 'pyproject.toml').exists() or (scan_dir / 'setup.py').exists():
                    repo_name = scan_dir.name if scan_dir.name != 'scan' else repo_name
            except Exception:
                repo_name = "mounted-repository"
                
            return jsonify({
                'path': '/app/scan',
                'display_name': repo_name
            })
        else:
            current_dir = Path(os.getcwd())
            repo_path = current_dir
            repo_name = current_dir.name

            try:
                result = subprocess.run(
                    ['git', 'rev-parse', '--show-toplevel'],
                    cwd=current_dir,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    repo_path = Path(result.stdout.strip())
                    repo_name = repo_path.name
            except Exception:
                pass

            return jsonify({
                'path': str(repo_path),
                'display_name': repo_name
            })
    except Exception as e:
        logger.error(f"Error getting current directory: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/discover-repos', methods=['GET'])
def discover_repositories():
    """Discover repositories in common locations."""
    try:
        repositories = []
        
        # Common repository locations
        home_dir = Path.home()
        search_paths = [
            home_dir / "repos",
            home_dir / "code", 
            home_dir / "projects",
            home_dir / "Documents",
            home_dir / "Desktop",
            home_dir / "Downloads"
        ]
        
        for search_path in search_paths:
            if search_path.exists() and search_path.is_dir():
                try:
                    # Look for directories with .git folders or package.json files
                    for item in search_path.iterdir():
                        if item.is_dir() and not item.name.startswith('.'):
                            repo_info = {
                                'name': item.name,
                                'path': str(item),
                                'type': 'directory'
                            }
                            
                            # Check if it's a git repository
                            if (item / '.git').exists():
                                repo_info['type'] = 'git'
                            # Check if it's a Node.js project
                            elif (item / 'package.json').exists():
                                repo_info['type'] = 'nodejs'
                            # Check if it's a Python project
                            elif (item / 'requirements.txt').exists() or (item / 'pyproject.toml').exists():
                                repo_info['type'] = 'python'
                            
                            repositories.append(repo_info)
                            
                            # Limit to prevent overwhelming the UI
                            if len(repositories) >= 20:
                                break
                                
                except (PermissionError, OSError):
                    # Skip directories we can't access
                    continue
                    
            if len(repositories) >= 20:
                break
        
        # Sort by name
        repositories.sort(key=lambda x: x['name'].lower())
        
        return jsonify({'repositories': repositories})
        
    except Exception as e:
        logger.error(f"Error discovering repositories: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    import datetime
    
    # Track web interface startup
    track_usage()
    
    # Get port from environment variable (for Docker/App Runner compatibility)
    port = int(os.environ.get('PORT', 8000))
    
    print("="*80)
    print("🔒 AppSec-Sentinel Web Interface - © 2025 Open Source")
    print("="*80)
    print(f"🚀 Starting Web API... [{datetime.datetime.now()}]")
    print(f"🌐 Listening on port: {port}")
    print("📖 MIT Licensed - Free for personal and commercial use")
    print("="*80)
    print()
    print("📖 API Documentation:")
    print("  GET  /health          - Health check")
    print("  GET  /config          - Get scanner configuration") 
    print("  POST /scan            - Run security scan")
    print("  GET  /report          - View HTML report")
    print("  GET  /reports/<file>  - Download specific report files")
    print()
    print("💡 Example scan request:")
    print(f'  curl -X POST http://localhost:{port}/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"repo_path": "/path/to/repo", "scan_level": "critical-high"}\'')
    print()
    print("📊 Usage analytics enabled for IP monitoring while repository is public")
    print("="*80)
    
    # Run Flask development server
    app.run(
        host='0.0.0.0',  # Accept connections from any IP
        port=port,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
