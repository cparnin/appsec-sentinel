#!/usr/bin/env python3
"""
Paid Security Tool Ingestion Framework

Ingests findings from paid security tools (Snyk, Veracode, Checkmarx, etc.)
and enhances them with AI context and cross-file analysis.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class SecurityToolIngester(ABC):
    """Abstract base class for security tool ingesters"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.findings = []
    
    @abstractmethod
    async def fetch_findings(self, **kwargs) -> List[Dict[str, Any]]:
        """Fetch findings from the security tool"""
        pass
    
    @abstractmethod
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize findings to our standard format"""
        pass
    
    async def ingest_findings(self, **kwargs) -> Dict[str, Any]:
        """Main ingestion method"""
        try:
            logger.info(f"🔄 Ingesting findings from {self.tool_name}...")
            
            # Fetch raw findings
            raw_findings = await self.fetch_findings(**kwargs)
            
            # Normalize to standard format
            normalized_findings = self.normalize_findings(raw_findings)
            
            # Add metadata
            result = {
                "tool": self.tool_name,
                "ingested_at": datetime.now().isoformat(),
                "total_findings": len(normalized_findings),
                "findings": normalized_findings,
                "metadata": {
                    "ingestion_method": "API" if hasattr(self, 'api_key') else "File",
                    "raw_count": len(raw_findings)
                }
            }
            
            logger.info(f"✅ Ingested {len(normalized_findings)} findings from {self.tool_name}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Failed to ingest from {self.tool_name}: {e}")
            return {
                "tool": self.tool_name,
                "error": str(e),
                "findings": [],
                "total_findings": 0
            }

class SnykIngester(SecurityToolIngester):
    """Ingest findings from Snyk"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("Snyk")
        self.api_key = api_key or os.getenv('SNYK_API_KEY')
        self.base_url = "https://snyk.io/api/v1"
    
    async def fetch_findings(self, org_id: str = None, project_id: str = None, 
                           file_path: str = None) -> List[Dict[str, Any]]:
        """Fetch findings from Snyk API or file"""
        
        if file_path:
            # Load from file
            return self._load_from_file(file_path)
        
        if not self.api_key:
            raise ValueError("Snyk API key required for API ingestion")
        
        # Fetch from API
        return await self._fetch_from_api(org_id, project_id)
    
    def _load_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Load Snyk findings from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle different Snyk export formats
            if isinstance(data, list):
                return data
            elif "vulnerabilities" in data:
                return data["vulnerabilities"]
            elif "issues" in data:
                return data["issues"]
            else:
                return [data]  # Single finding
                
        except Exception as e:
            logger.error(f"Failed to load Snyk file {file_path}: {e}")
            return []
    
    async def _fetch_from_api(self, org_id: str, project_id: str = None) -> List[Dict[str, Any]]:
        """Fetch findings from Snyk API"""
        headers = {
            "Authorization": f"token {self.api_key}",
            "Content-Type": "application/json"
        }
        
        findings = []
        
        try:
            if project_id:
                # Fetch specific project
                url = f"{self.base_url}/org/{org_id}/project/{project_id}/issues"
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                findings.extend(data.get("issues", []))
            else:
                # Fetch all projects in org
                projects_url = f"{self.base_url}/org/{org_id}/projects"
                response = requests.get(projects_url, headers=headers)
                response.raise_for_status()
                projects = response.json().get("projects", [])
                
                for project in projects:
                    proj_id = project["id"]
                    url = f"{self.base_url}/org/{org_id}/project/{proj_id}/issues"
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        findings.extend(data.get("issues", []))
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to fetch from Snyk API: {e}")
            return []
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize Snyk findings to our standard format"""
        normalized = []
        
        for finding in raw_findings:
            try:
                # Extract common fields
                normalized_finding = {
                    "tool": "snyk",
                    "id": finding.get("id", "unknown"),
                    "title": finding.get("title", finding.get("issueData", {}).get("title", "Unknown Issue")),
                    "severity": self._normalize_severity(finding.get("issueData", {}).get("severity", "medium")),
                    "type": finding.get("issueType", "vulnerability"),
                    "description": finding.get("issueData", {}).get("description", ""),
                    "package": finding.get("pkgName", ""),
                    "version": finding.get("pkgVersion", ""),
                    "path": finding.get("from", []),
                    "cve": finding.get("issueData", {}).get("identifiers", {}).get("CVE", []),
                    "cwe": finding.get("issueData", {}).get("identifiers", {}).get("CWE", []),
                    "cvss_score": finding.get("issueData", {}).get("cvssScore"),
                    "is_upgradable": finding.get("isUpgradable", False),
                    "is_patchable": finding.get("isPatchable", False),
                    "is_pinnable": finding.get("isPinnable", False),
                    "priority_score": finding.get("priorityScore"),
                    "introduced_date": finding.get("introducedDate"),
                    "disclosed_date": finding.get("issueData", {}).get("publicationTime"),
                    "exploit_maturity": finding.get("issueData", {}).get("exploitMaturity"),
                    "raw_finding": finding  # Keep original for reference
                }
                
                # Add upgrade/patch information
                if finding.get("upgradePath"):
                    normalized_finding["upgrade_path"] = finding["upgradePath"]
                
                if finding.get("patches"):
                    normalized_finding["patches"] = finding["patches"]
                
                normalized.append(normalized_finding)
                
            except Exception as e:
                logger.debug(f"Failed to normalize Snyk finding: {e}")
                # Add minimal normalized finding
                normalized.append({
                    "tool": "snyk",
                    "id": finding.get("id", "unknown"),
                    "title": "Failed to parse",
                    "severity": "medium",
                    "type": "vulnerability",
                    "raw_finding": finding
                })
        
        return normalized
    
    def _normalize_severity(self, snyk_severity: str) -> str:
        """Convert Snyk severity to our standard format"""
        severity_mapping = {
            "critical": "CRITICAL",
            "high": "HIGH", 
            "medium": "MEDIUM",
            "low": "LOW"
        }
        return severity_mapping.get(snyk_severity.lower(), "MEDIUM")

class VeracodeIngester(SecurityToolIngester):
    """Ingest findings from Veracode"""
    
    def __init__(self, api_id: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__("Veracode")
        self.api_id = api_id or os.getenv('VERACODE_API_ID')
        self.api_key = api_key or os.getenv('VERACODE_API_KEY')
        self.base_url = "https://api.veracode.com/appsec/v1"
    
    async def fetch_findings(self, app_id: str = None, file_path: str = None) -> List[Dict[str, Any]]:
        """Fetch findings from Veracode API or file"""
        
        if file_path:
            return self._load_from_file(file_path)
        
        if not self.api_id or not self.api_key:
            raise ValueError("Veracode API credentials required for API ingestion")
        
        return await self._fetch_from_api(app_id)
    
    def _load_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Load Veracode findings from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle Veracode XML-to-JSON exports
            if "detailedreport" in data:
                return data["detailedreport"].get("findings", [])
            elif "findings" in data:
                return data["findings"]
            elif isinstance(data, list):
                return data
            else:
                return [data]
                
        except Exception as e:
            logger.error(f"Failed to load Veracode file {file_path}: {e}")
            return []
    
    async def _fetch_from_api(self, app_id: str) -> List[Dict[str, Any]]:
        """Fetch findings from Veracode API"""
        # Note: Veracode API requires HMAC authentication - simplified here
        logger.warning("Veracode API integration requires HMAC authentication - use file ingestion for now")
        return []
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize Veracode findings to our standard format"""
        normalized = []
        
        for finding in raw_findings:
            try:
                normalized_finding = {
                    "tool": "veracode",
                    "id": finding.get("issue_id", finding.get("flaw_id", "unknown")),
                    "title": finding.get("cwename", finding.get("categoryname", "Unknown Issue")),
                    "severity": self._normalize_severity(finding.get("severity", "3")),
                    "type": "vulnerability",
                    "description": finding.get("description", ""),
                    "file": finding.get("file", ""),
                    "line": finding.get("line", ""),
                    "cwe": [finding.get("cweid")] if finding.get("cweid") else [],
                    "remediation_effort": finding.get("remediation_effort", ""),
                    "exploit_level": finding.get("exploitLevel", ""),
                    "raw_finding": finding
                }
                
                normalized.append(normalized_finding)
                
            except Exception as e:
                logger.debug(f"Failed to normalize Veracode finding: {e}")
                normalized.append({
                    "tool": "veracode",
                    "id": finding.get("issue_id", "unknown"),
                    "title": "Failed to parse",
                    "severity": "MEDIUM",
                    "type": "vulnerability",
                    "raw_finding": finding
                })
        
        return normalized
    
    def _normalize_severity(self, veracode_severity: str) -> str:
        """Convert Veracode severity (1-5) to our standard format"""
        severity_mapping = {
            "5": "CRITICAL",
            "4": "HIGH",
            "3": "MEDIUM", 
            "2": "LOW",
            "1": "LOW"
        }
        return severity_mapping.get(str(veracode_severity), "MEDIUM")

class GenericIngester(SecurityToolIngester):
    """Generic ingester for tools with JSON export"""
    
    def __init__(self, tool_name: str):
        super().__init__(tool_name)
    
    async def fetch_findings(self, file_path: str) -> List[Dict[str, Any]]:
        """Load findings from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                return data
            elif "findings" in data:
                return data["findings"]
            elif "issues" in data:
                return data["issues"]
            elif "vulnerabilities" in data:
                return data["vulnerabilities"]
            else:
                return [data]
                
        except Exception as e:
            logger.error(f"Failed to load {self.tool_name} file {file_path}: {e}")
            return []
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Basic normalization for generic tools"""
        normalized = []
        
        for finding in raw_findings:
            # Try to extract common fields
            normalized_finding = {
                "tool": self.tool_name.lower(),
                "id": finding.get("id", finding.get("uuid", "unknown")),
                "title": finding.get("title", finding.get("name", finding.get("rule", "Unknown Issue"))),
                "severity": self._normalize_severity(finding.get("severity", "medium")),
                "type": finding.get("type", "vulnerability"),
                "description": finding.get("description", finding.get("message", "")),
                "file": finding.get("file", finding.get("path", "")),
                "line": finding.get("line", finding.get("line_number", "")),
                "raw_finding": finding
            }
            
            normalized.append(normalized_finding)
        
        return normalized
    
    def _normalize_severity(self, severity: str) -> str:
        """Basic severity normalization"""
        if isinstance(severity, (int, float)):
            if severity >= 9:
                return "CRITICAL"
            elif severity >= 7:
                return "HIGH"
            elif severity >= 4:
                return "MEDIUM"
            else:
                return "LOW"
        
        severity_str = str(severity).lower()
        if "critical" in severity_str or "crit" in severity_str:
            return "CRITICAL"
        elif "high" in severity_str:
            return "HIGH"
        elif "medium" in severity_str or "med" in severity_str:
            return "MEDIUM"
        elif "low" in severity_str:
            return "LOW"
        else:
            return "MEDIUM"

class ToolIngestionManager:
    """Manages ingestion from multiple security tools"""
    
    def __init__(self):
        self.ingesters = {}
        self.setup_ingesters()
    
    def setup_ingesters(self):
        """Setup available ingesters"""
        self.ingesters["snyk"] = SnykIngester()
        self.ingesters["veracode"] = VeracodeIngester()
        # Add more as needed
    
    async def ingest_from_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Ingest from a specific tool"""
        if tool_name.lower() not in self.ingesters:
            # Use generic ingester
            ingester = GenericIngester(tool_name)
        else:
            ingester = self.ingesters[tool_name.lower()]
        
        return await ingester.ingest_findings(**kwargs)
    
    async def ingest_multiple_tools(self, tool_configs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ingest from multiple tools"""
        results = {}
        
        for config in tool_configs:
            tool_name = config.get("tool")
            if not tool_name:
                continue
            
            try:
                result = await self.ingest_from_tool(tool_name, **config.get("params", {}))
                results[tool_name] = result
            except Exception as e:
                logger.error(f"Failed to ingest from {tool_name}: {e}")
                results[tool_name] = {
                    "tool": tool_name,
                    "error": str(e),
                    "findings": [],
                    "total_findings": 0
                }
        
        return results
    
    def save_ingested_findings(self, results: Dict[str, Any], output_dir: str = "outputs/raw"):
        """Save ingested findings to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for tool_name, result in results.items():
            if result.get("findings"):
                filename = f"{tool_name}_ingested.json"
                file_path = output_path / filename
                
                with open(file_path, 'w') as f:
                    json.dump(result, f, indent=2)
                
                logger.info(f"💾 Saved {tool_name} findings to {file_path}")

# Example usage and configuration
async def ingest_client_tools(config_file: str = None) -> Dict[str, Any]:
    """
    Ingest findings from client's paid security tools
    
    Args:
        config_file: Path to configuration file with tool settings
        
    Returns:
        Dict with ingestion results from all tools
    """
    manager = ToolIngestionManager()
    
    # Default configuration for common scenarios
    default_configs = [
        {
            "tool": "snyk",
            "params": {
                "file_path": "clients/client_exports/snyk_export.json"
            }
        },
        {
            "tool": "veracode",
            "params": {
                "file_path": "clients/client_exports/veracode_export.json"
            }
        }
    ]
    
    # Load custom configuration if provided
    if config_file and Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                configs = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            configs = default_configs
    else:
        configs = default_configs
    
    # Ingest from all configured tools
    results = await manager.ingest_multiple_tools(configs)
    
    # Save results
    manager.save_ingested_findings(results)
    
    return results

if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        # Test ingestion
        results = await ingest_client_tools()
        print(f"Ingested findings from {len(results)} tools")
        
        for tool, result in results.items():
            if "error" in result:
                print(f"❌ {tool}: {result['error']}")
            else:
                print(f"✅ {tool}: {result['total_findings']} findings")
    
    asyncio.run(main())