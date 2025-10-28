from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

def generate_html_report(findings: List[Dict[str, Any]], ai_summary: str, output_dir: str, repo_path: Optional[str] = None, detected_languages: Optional[set] = None) -> str:
    """
    Generate an HTML report from the scanner findings.

    Args:
        findings (list): List of all findings from scanners
        ai_summary (str): AI-generated executive summary
        output_dir (str): Directory to write the HTML report
        repo_path (str): Path to the scanned repository
        detected_languages (set): Set of detected programming languages
    """
    
    def sort_by_severity(finding):
        """Sort findings by severity priority: Critical > High > Error"""
        severity = (finding.get('extra', {}).get('severity') or 
                   finding.get('severity', '')).lower()
        
        # Map severity to sort order (lower number = higher priority)
        # Only critical, high, and error since we filter out warning/medium
        severity_order = {
            'critical': 1,
            'error': 2,    # Semgrep uses ERROR for high severity
            'high': 2, 
            '': 6          # Unknown severity goes last
        }
        return severity_order.get(severity, 6)
    
    try:
        # Convert output_dir to Path object if it's a string
        output_path = Path(output_dir)
        
        # Group findings by tool
        results = {}
        for finding in findings:
            tool = finding.get('tool', 'unknown')
            if tool not in results:
                results[tool] = []
            results[tool].append(finding)
        
        # Load Jinja2 template
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html")
        
        # Sort findings by severity for each tool
        sorted_results = {}
        for tool, tool_findings in results.items():
            if tool_findings:
                sorted_results[tool] = sorted(tool_findings, key=sort_by_severity)
            else:
                sorted_results[tool] = tool_findings
        
        # Count total findings and severity breakdown
        total_findings = len(findings)
        critical_count = 0
        high_count = 0
        cross_file_enhanced_count = 0
        attack_chains_count = 0
        
        # Extract cross-file analysis data for enhanced reporting with smart limits
        cross_file_context_data = {
            'frameworks_detected': set(),
            'languages_detected': set(),
            'attack_chains': [],
            'business_impacts': [],
            'cross_file_vulnerabilities': []
        }
        
        # Adaptive limits based on total findings (prevent wall of text)
        is_large_scan = total_findings > 20  # Likely intentionally vulnerable repo
        max_attack_chains = 3 if is_large_scan else 5
        max_business_impacts = 5 if is_large_scan else 8  # Expanded from 2->5, 3->8
        
        for finding in findings:
            severity = (finding.get('extra', {}).get('severity') or 
                       finding.get('severity', '')).lower()
            if severity == 'critical':
                critical_count += 1
            elif severity in ['high', 'error']:
                high_count += 1
            
            # Extract cross-file analysis data from findings
            if finding.get('cross_file_analysis'):
                cross_file_enhanced_count += 1
                
                # Extract cross-file analysis with limits
                cross_file = finding.get('cross_file_analysis', {})
                if cross_file.get('potential_attack_chains') and len(cross_file_context_data['attack_chains']) < max_attack_chains * 2:
                    for chain in cross_file['potential_attack_chains']:
                        if len(cross_file_context_data['attack_chains']) >= max_attack_chains * 2:
                            break
                        cross_file_context_data['attack_chains'].append({
                            'type': chain.get('chain_type', 'Unknown'),
                            'severity': chain.get('severity', 'Unknown'),
                            'entry_point': chain.get('entry_point', 'Unknown'),
                            'sink': chain.get('sink', 'Unknown'),
                            'description': chain.get('description', ''),
                            'files_involved': len(chain.get('attack_path', [])),
                            'priority': 1 if chain.get('severity', '').lower() in ['critical', 'high'] else 2
                        })
                        attack_chains_count += 1
                
                # Extract business impact data with limits
                business_impact = finding.get('business_impact', {})
                if business_impact.get('business_justification') and len(cross_file_context_data['business_impacts']) < max_business_impacts * 2:
                    cross_file_context_data['business_impacts'].append({
                        'file': finding.get('path', ''),
                        'vulnerability': finding.get('check_id', ''),
                        'impact': business_impact.get('business_justification', ''),
                        'financial_risk': business_impact.get('financial_risk', 'Unknown'),
                        'priority': 1 if business_impact.get('financial_risk', '').lower() == 'high' else 2
                    })
            
            # Extract technology stack info from cross-file analysis summaries
            cross_file_summary = finding.get('cross_file_summary', '')
            if 'Tech:' in cross_file_summary:
                tech_part = cross_file_summary.split('Tech:')[-1].strip()
                if tech_part:
                    frameworks = [fw.strip() for fw in tech_part.split(',')]
                    cross_file_context_data['frameworks_detected'].update(frameworks)
        
        # Sort and limit data for template
        cross_file_context_data['frameworks_detected'] = list(cross_file_context_data['frameworks_detected'])[:8]  # Max 8 frameworks
        cross_file_context_data['languages_detected'] = list(cross_file_context_data['languages_detected'])
        
        # Sort attack chains by priority (critical/high first) and limit
        cross_file_context_data['attack_chains'] = sorted(cross_file_context_data['attack_chains'], 
                                                  key=lambda x: (x.get('priority', 2), x.get('type', '')))
        cross_file_context_data['attack_chains'] = cross_file_context_data['attack_chains'][:max_attack_chains]
        
        # Sort business impacts by priority and limit
        cross_file_context_data['business_impacts'] = sorted(cross_file_context_data['business_impacts'],
                                                     key=lambda x: (x.get('priority', 2), x.get('file', '')))
        cross_file_context_data['business_impacts'] = cross_file_context_data['business_impacts'][:max_business_impacts]
        
        # Add metadata for template
        cross_file_context_data['is_large_scan'] = is_large_scan
        cross_file_context_data['max_attack_chains'] = max_attack_chains
        cross_file_context_data['max_business_impacts'] = max_business_impacts
        
        # Look for SBOM data in outputs directory
        sbom_data = {}
        sbom_files = ['sbom.cyclonedx.json', 'sbom.spdx.json']
        output_path_obj = Path(output_dir)
        
        logger.debug(f"Looking for SBOM files in: {output_path_obj / 'sbom'}")
        
        for sbom_file in sbom_files:
            sbom_path = output_path_obj / 'sbom' / sbom_file
            logger.debug(f"Checking SBOM file: {sbom_path} (exists: {sbom_path.exists()})")
            if sbom_path.exists():
                try:
                    import json
                    with open(sbom_path, 'r') as f:
                        sbom_content = json.load(f)
                        # Extract key information for display
                        if 'components' in sbom_content:  # CycloneDX format
                            sbom_data[sbom_file] = {
                                'format': 'CycloneDX',
                                'components': len(sbom_content.get('components', [])),
                                'dependencies': len(sbom_content.get('dependencies', [])),
                                'file': sbom_file
                            }
                            logger.debug(f"Added CycloneDX SBOM data: {len(sbom_content.get('components', []))} components")
                        elif 'packages' in sbom_content:  # SPDX format
                            sbom_data[sbom_file] = {
                                'format': 'SPDX',
                                'packages': len(sbom_content.get('packages', [])),
                                'relationships': len(sbom_content.get('relationships', [])),
                                'file': sbom_file
                            }
                            logger.debug(f"Added SPDX SBOM data: {len(sbom_content.get('packages', []))} packages")
                except Exception as e:
                    logger.error(f"Could not parse SBOM file {sbom_file}: {e}")
        
        logger.debug(f"Final SBOM data for template: {sbom_data}")
        
        # Render template with findings data
        # Add timestamp for when report was generated (Eastern Time)
        from zoneinfo import ZoneInfo
        eastern = ZoneInfo("America/New_York")
        scan_timestamp = datetime.now(eastern).strftime("%Y-%m-%d %H:%M:%S EST")
        
        html_content = template.render(
            results=sorted_results,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            ai_summary=ai_summary,
            repo_path=repo_path or "Unknown Repository",
            sbom_data=sbom_data,
            scan_timestamp=scan_timestamp,
            cross_file_enhanced_count=cross_file_enhanced_count,
            attack_chains_count=attack_chains_count,
            cross_file_context_data=cross_file_context_data,
            detected_languages=sorted(detected_languages) if detected_languages else []
        )
        
        # Write HTML report
        report_path = output_path / "report.html"
        report_path.write_text(html_content)
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)
        
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        # Create fallback report
        fallback_html = """
        <html>
        <head><title>Security Scan Report</title></head>
        <body>
        <h1>Security Scan Report</h1>
        <p><strong>Error:</strong> Failed to generate full report.</p>
        <p>Check the logs for details.</p>
        </body>
        </html>
        """
        output_path = Path(output_dir)
        fallback_path = output_path / "report.html"
        fallback_path.write_text(fallback_html)
        return str(fallback_path)