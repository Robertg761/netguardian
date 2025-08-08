#!/usr/bin/env python3
"""
NetGuardian CVE Database Integration Module
Provides vulnerability database lookup and matching capabilities.
"""

import logging
import json
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import sqlite3
import os
import hashlib
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not available. Install with: pip install requests")

class CVEDatabase:
    """
    A class for CVE (Common Vulnerabilities and Exposures) database integration.
    Provides vulnerability lookup, matching, and severity assessment.
    """
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize the CVE Database.
        
        Args:
            cache_dir: Directory for caching CVE data
        """
        self.logger = logging.getLogger(__name__)
        
        # Set up cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.netguardian' / 'cve_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize SQLite database for caching
        self.db_path = self.cache_dir / 'cve_database.db'
        self._init_database()
        
        # API endpoints
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circl_api_base = "https://cve.circl.lu/api"
        
        # CVE severity levels
        self.severity_levels = {
            'CRITICAL': {'score_range': (9.0, 10.0), 'color': '#ff0000'},
            'HIGH': {'score_range': (7.0, 8.9), 'color': '#ff8800'},
            'MEDIUM': {'score_range': (4.0, 6.9), 'color': '#ffcc00'},
            'LOW': {'score_range': (0.1, 3.9), 'color': '#00cc00'},
            'NONE': {'score_range': (0.0, 0.0), 'color': '#888888'}
        }
        
    def _init_database(self):
        """Initialize SQLite database for CVE caching."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published_date TEXT,
                modified_date TEXT,
                cpe_list TEXT,
                references TEXT,
                last_updated INTEGER,
                raw_data TEXT
            )
        ''')
        
        # Create service-CVE mapping table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_cves (
                service_name TEXT,
                version TEXT,
                cve_id TEXT,
                confidence REAL,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_service ON service_cves (service_name, version)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON cves (severity, cvss_score DESC)')
        
        conn.commit()
        conn.close()
    
    def search_vulnerabilities(self, product: str, version: str = None,
                             use_cache: bool = True, 
                             cache_duration: int = 86400) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities for a specific product/version.
        
        Args:
            product: Product name (e.g., 'apache', 'nginx')
            version: Product version (optional)
            use_cache: Whether to use cached results
            cache_duration: Cache validity in seconds (default: 24 hours)
            
        Returns:
            List of CVE entries
        """
        # Generate cache key
        cache_key = f"{product}:{version if version else 'all'}"
        
        # Check cache if enabled
        if use_cache:
            cached_results = self._get_cached_cves(cache_key, cache_duration)
            if cached_results:
                self.logger.debug(f"Using cached CVEs for {cache_key}")
                return cached_results
        
        # Search for CVEs
        cves = []
        
        # Try NVD API first
        if HAS_REQUESTS:
            nvd_cves = self._search_nvd(product, version)
            cves.extend(nvd_cves)
        
        # Also check our local database
        local_cves = self._search_local_db(product, version)
        
        # Merge and deduplicate
        seen_ids = set()
        unique_cves = []
        for cve in cves + local_cves:
            if cve['cve_id'] not in seen_ids:
                seen_ids.add(cve['cve_id'])
                unique_cves.append(cve)
        
        # Sort by CVSS score (highest first)
        unique_cves.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        # Cache results
        if unique_cves:
            self._cache_cves(cache_key, unique_cves)
        
        return unique_cves
    
    def _search_nvd(self, product: str, version: str = None) -> List[Dict[str, Any]]:
        """Search NVD (National Vulnerability Database) for CVEs."""
        if not HAS_REQUESTS:
            return []
        
        cves = []
        
        try:
            # Build query
            params = {
                'keywordSearch': product,
                'resultsPerPage': 50
            }
            
            # Make request
            response = requests.get(self.nvd_api_base, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    
                    # Extract CVE information
                    cve_id = cve_data.get('id', '')
                    
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Get CVSS score
                    cvss_score = 0.0
                    severity = 'NONE'
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'NONE')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'NONE')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = self._score_to_severity(cvss_score)
                    
                    # Get dates
                    published = cve_data.get('published', '')
                    modified = cve_data.get('lastModified', '')
                    
                    # Get references
                    references = []
                    for ref in cve_data.get('references', []):
                        references.append({
                            'url': ref.get('url', ''),
                            'source': ref.get('source', '')
                        })
                    
                    # Check if version matches (if specified)
                    if version and not self._version_matches(cve_data, product, version):
                        continue
                    
                    cves.append({
                        'cve_id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published_date': published,
                        'modified_date': modified,
                        'references': references,
                        'product': product,
                        'version': version
                    })
            
        except Exception as e:
            self.logger.error(f"Error searching NVD: {e}")
        
        return cves
    
    def _search_local_db(self, product: str, version: str = None) -> List[Dict[str, Any]]:
        """Search local SQLite database for CVEs."""
        cves = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if version:
                query = '''
                    SELECT c.* FROM cves c
                    JOIN service_cves sc ON c.cve_id = sc.cve_id
                    WHERE sc.service_name LIKE ? AND sc.version = ?
                    ORDER BY c.cvss_score DESC
                '''
                cursor.execute(query, (f'%{product}%', version))
            else:
                query = '''
                    SELECT DISTINCT c.* FROM cves c
                    JOIN service_cves sc ON c.cve_id = sc.cve_id
                    WHERE sc.service_name LIKE ?
                    ORDER BY c.cvss_score DESC
                '''
                cursor.execute(query, (f'%{product}%',))
            
            for row in cursor.fetchall():
                cve = {
                    'cve_id': row[0],
                    'description': row[1],
                    'cvss_score': row[2],
                    'severity': row[3],
                    'published_date': row[4],
                    'modified_date': row[5],
                    'references': json.loads(row[7]) if row[7] else [],
                    'product': product,
                    'version': version
                }
                cves.append(cve)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error searching local database: {e}")
        
        return cves
    
    def analyze_service_vulnerabilities(self, services: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities for a list of services.
        
        Args:
            services: List of service dictionaries with 'name' and 'version' keys
            
        Returns:
            Analysis results with vulnerability statistics and details
        """
        results = {
            'total_services': len(services),
            'vulnerable_services': 0,
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'services': {}
        }
        
        for service in services:
            service_name = service.get('name', '').lower()
            version = service.get('version', '')
            
            if not service_name:
                continue
            
            # Search for vulnerabilities
            cves = self.search_vulnerabilities(service_name, version)
            
            if cves:
                results['vulnerable_services'] += 1
                results['total_vulnerabilities'] += len(cves)
                
                # Count by severity
                for cve in cves:
                    severity = cve.get('severity', 'NONE').upper()
                    if severity == 'CRITICAL':
                        results['critical_count'] += 1
                    elif severity == 'HIGH':
                        results['high_count'] += 1
                    elif severity == 'MEDIUM':
                        results['medium_count'] += 1
                    elif severity == 'LOW':
                        results['low_count'] += 1
                
                # Store service-specific results
                results['services'][f"{service_name}:{version}"] = {
                    'name': service_name,
                    'version': version,
                    'vulnerability_count': len(cves),
                    'highest_severity': cves[0].get('severity') if cves else 'NONE',
                    'highest_cvss': cves[0].get('cvss_score') if cves else 0.0,
                    'cves': cves[:10]  # Limit to top 10 CVEs
                }
        
        # Calculate risk score
        results['risk_score'] = self._calculate_risk_score(results)
        results['risk_level'] = self._get_risk_level(results['risk_score'])
        
        return results
    
    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score based on vulnerability analysis."""
        if analysis['total_services'] == 0:
            return 0.0
        
        # Weighted scoring
        score = 0.0
        score += analysis['critical_count'] * 10.0
        score += analysis['high_count'] * 7.0
        score += analysis['medium_count'] * 4.0
        score += analysis['low_count'] * 1.0
        
        # Normalize by number of services
        score = score / analysis['total_services']
        
        # Cap at 10.0
        return min(score, 10.0)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on risk score."""
        if risk_score >= 8.0:
            return 'CRITICAL'
        elif risk_score >= 6.0:
            return 'HIGH'
        elif risk_score >= 4.0:
            return 'MEDIUM'
        elif risk_score >= 2.0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _version_matches(self, cve_data: Dict, product: str, version: str) -> bool:
        """Check if a CVE applies to a specific product version."""
        # This is a simplified version check
        # In production, you'd want to parse CPE strings properly
        
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        cpe_string = cpe_match.get('criteria', '')
                        
                        # Check if product name is in CPE
                        if product.lower() not in cpe_string.lower():
                            continue
                        
                        # Check version range
                        version_start = cpe_match.get('versionStartIncluding')
                        version_end = cpe_match.get('versionEndExcluding')
                        
                        if version_start or version_end:
                            # Simple version comparison (would need proper version parsing in production)
                            if version_start and version < version_start:
                                continue
                            if version_end and version >= version_end:
                                continue
                        
                        return True
        
        # If no specific version info, assume it might apply
        return True
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        for severity, info in self.severity_levels.items():
            min_score, max_score = info['score_range']
            if min_score <= score <= max_score:
                return severity
        return 'NONE'
    
    def _get_cached_cves(self, cache_key: str, cache_duration: int) -> Optional[List[Dict[str, Any]]]:
        """Retrieve cached CVEs if still valid."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate cache expiry time
            expiry_time = int(time.time()) - cache_duration
            
            # Query for cached CVEs
            query = '''
                SELECT c.* FROM cves c
                JOIN service_cves sc ON c.cve_id = sc.cve_id
                WHERE sc.service_name = ? AND c.last_updated > ?
            '''
            
            cursor.execute(query, (cache_key, expiry_time))
            
            cves = []
            for row in cursor.fetchall():
                cve = {
                    'cve_id': row[0],
                    'description': row[1],
                    'cvss_score': row[2],
                    'severity': row[3],
                    'published_date': row[4],
                    'modified_date': row[5],
                    'references': json.loads(row[7]) if row[7] else []
                }
                cves.append(cve)
            
            conn.close()
            
            return cves if cves else None
            
        except Exception as e:
            self.logger.error(f"Error retrieving cached CVEs: {e}")
            return None
    
    def _cache_cves(self, cache_key: str, cves: List[Dict[str, Any]]):
        """Cache CVE results."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            current_time = int(time.time())
            
            for cve in cves:
                # Insert or update CVE
                cursor.execute('''
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, cvss_score, severity, published_date, 
                     modified_date, references, last_updated, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve['cve_id'],
                    cve.get('description', ''),
                    cve.get('cvss_score', 0.0),
                    cve.get('severity', 'NONE'),
                    cve.get('published_date', ''),
                    cve.get('modified_date', ''),
                    json.dumps(cve.get('references', [])),
                    current_time,
                    json.dumps(cve)
                ))
                
                # Link to service
                product, version = cache_key.split(':', 1)
                cursor.execute('''
                    INSERT OR REPLACE INTO service_cves
                    (service_name, version, cve_id, confidence)
                    VALUES (?, ?, ?, ?)
                ''', (product, version if version != 'all' else '', cve['cve_id'], 1.0))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error caching CVEs: {e}")
    
    def generate_vulnerability_report(self, analysis: Dict[str, Any], 
                                     filepath: str, format: str = 'html') -> None:
        """
        Generate a vulnerability report.
        
        Args:
            analysis: Results from analyze_service_vulnerabilities
            filepath: Output file path
            format: Report format ('html', 'json', 'txt')
        """
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
        
        elif format == 'html':
            html_content = self._generate_html_report(analysis)
            with open(filepath, 'w') as f:
                f.write(html_content)
        
        elif format == 'txt':
            with open(filepath, 'w') as f:
                f.write("VULNERABILITY ANALYSIS REPORT\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"Risk Level: {analysis['risk_level']}\n")
                f.write(f"Risk Score: {analysis['risk_score']:.2f}/10.0\n\n")
                
                f.write("SUMMARY\n")
                f.write("-" * 30 + "\n")
                f.write(f"Total Services Analyzed: {analysis['total_services']}\n")
                f.write(f"Vulnerable Services: {analysis['vulnerable_services']}\n")
                f.write(f"Total Vulnerabilities: {analysis['total_vulnerabilities']}\n\n")
                
                f.write("SEVERITY BREAKDOWN\n")
                f.write("-" * 30 + "\n")
                f.write(f"Critical: {analysis['critical_count']}\n")
                f.write(f"High: {analysis['high_count']}\n")
                f.write(f"Medium: {analysis['medium_count']}\n")
                f.write(f"Low: {analysis['low_count']}\n\n")
                
                f.write("VULNERABLE SERVICES\n")
                f.write("-" * 30 + "\n")
                for service_key, service_data in analysis['services'].items():
                    f.write(f"\n{service_data['name']} {service_data['version']}\n")
                    f.write(f"  Vulnerabilities: {service_data['vulnerability_count']}\n")
                    f.write(f"  Highest Severity: {service_data['highest_severity']}\n")
                    f.write(f"  Highest CVSS: {service_data['highest_cvss']}\n")
                    
                    for cve in service_data['cves'][:5]:  # Top 5 CVEs
                        f.write(f"    - {cve['cve_id']} ({cve['severity']}, CVSS: {cve['cvss_score']})\n")
        
        self.logger.info(f"Vulnerability report generated: {filepath}")
    
    def _generate_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate HTML vulnerability report."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff8800; font-weight: bold; }
        .medium { color: #ffcc00; }
        .low { color: #00cc00; }
        .service { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .cve-list { margin-top: 10px; padding-left: 20px; }
        .cve-item { margin: 5px 0; }
        .risk-badge { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .risk-critical { background: #ff0000; }
        .risk-high { background: #ff8800; }
        .risk-medium { background: #ffcc00; color: #333; }
        .risk-low { background: #00cc00; }
        .risk-minimal { background: #888888; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Analysis Report</h1>
        <p>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    </div>
    
    <div class="summary">
        <h2>Risk Assessment</h2>
        <p>Overall Risk Level: <span class="risk-badge risk-""" + analysis['risk_level'].lower() + '""">' + analysis['risk_level'] + """</span></p>
        <p>Risk Score: """ + f"{analysis['risk_score']:.2f}" + """/10.0</p>
        
        <h3>Summary Statistics</h3>
        <ul>
            <li>Total Services Analyzed: """ + str(analysis['total_services']) + """</li>
            <li>Vulnerable Services: """ + str(analysis['vulnerable_services']) + """</li>
            <li>Total Vulnerabilities: """ + str(analysis['total_vulnerabilities']) + """</li>
        </ul>
        
        <h3>Severity Breakdown</h3>
        <ul>
            <li class="critical">Critical: """ + str(analysis['critical_count']) + """</li>
            <li class="high">High: """ + str(analysis['high_count']) + """</li>
            <li class="medium">Medium: """ + str(analysis['medium_count']) + """</li>
            <li class="low">Low: """ + str(analysis['low_count']) + """</li>
        </ul>
    </div>
    
    <h2>Vulnerable Services</h2>
"""
        
        for service_key, service_data in analysis['services'].items():
            severity_class = service_data['highest_severity'].lower()
            html += f"""
    <div class="service">
        <h3>{service_data['name']} {service_data['version']}</h3>
        <p>Vulnerabilities Found: {service_data['vulnerability_count']}</p>
        <p>Highest Severity: <span class="{severity_class}">{service_data['highest_severity']}</span></p>
        <p>Highest CVSS Score: {service_data['highest_cvss']}</p>
        
        <div class="cve-list">
            <h4>Top CVEs:</h4>
"""
            
            for cve in service_data['cves'][:5]:
                severity_class = cve['severity'].lower()
                html += f"""
            <div class="cve-item">
                <strong>{cve['cve_id']}</strong> - 
                <span class="{severity_class}">{cve['severity']}</span> 
                (CVSS: {cve['cvss_score']})
                <br>
                <small>{cve['description'][:200]}...</small>
            </div>
"""
            
            html += """
        </div>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html
