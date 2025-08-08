#!/usr/bin/env python3
"""
NetGuardian Web Application Scanner Module
Provides web application security scanning capabilities.
"""

import logging
import time
import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
import socket
import ssl
import base64
from datetime import datetime

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not available. Install with: pip install requests")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("Warning: BeautifulSoup not available. Install with: pip install beautifulsoup4")

class WebApplicationScanner:
    """
    A class for web application security scanning including:
    - Technology detection
    - Security header analysis
    - SSL/TLS analysis
    - Common vulnerability checks
    - Directory and file discovery
    - Form analysis
    """
    
    def __init__(self):
        """Initialize the Web Application Scanner."""
        self.logger = logging.getLogger(__name__)
        
        # Setup session with retries
        if HAS_REQUESTS:
            self.session = requests.Session()
            retry = Retry(total=3, backoff_factor=0.3)
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
            
            # Set user agent
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (NetGuardian Security Scanner)'
            })
        
        # Common directories and files to check
        self.common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
            'api', 'v1', 'v2', 'graphql', 'swagger', 'docs', 'documentation',
            'backup', 'backups', 'old', 'test', 'dev', 'staging',
            '.git', '.svn', '.env', 'config', 'conf', 'settings',
            'upload', 'uploads', 'files', 'download', 'downloads',
            'images', 'img', 'css', 'js', 'static', 'assets',
            'cgi-bin', 'scripts', 'includes', 'private', 'tmp', 'temp'
        ]
        
        self.common_files = [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'security.txt',
            '.htaccess', 'web.config', 'wp-config.php', 'config.php',
            'database.php', 'db.php', 'settings.php', 'config.json',
            'package.json', 'composer.json', 'README.md', 'LICENSE',
            '.git/HEAD', '.env', '.env.local', '.env.production',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php',
            'backup.zip', 'backup.tar.gz', 'database.sql', 'dump.sql'
        ]
        
        # Security headers to check
        self.security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
        
        # Common web technologies patterns
        self.tech_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
            'Drupal': [r'drupal', r'sites/default', r'Drupal'],
            'Joomla': [r'joomla', r'/components/', r'Joomla'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'Flask': [r'werkzeug', r'flask'],
            'React': [r'react', r'_react', r'React'],
            'Angular': [r'ng-', r'angular', r'Angular'],
            'Vue.js': [r'vue', r'v-', r'Vue'],
            'jQuery': [r'jquery', r'jQuery'],
            'Bootstrap': [r'bootstrap', r'Bootstrap'],
            'PHP': [r'\.php', r'PHP/'],
            'ASP.NET': [r'ASP\.NET', r'__VIEWSTATE', r'\.aspx'],
            'Ruby on Rails': [r'rails', r'Ruby on Rails'],
            'Node.js': [r'node', r'express'],
            'Nginx': [r'nginx', r'Nginx'],
            'Apache': [r'Apache', r'apache'],
            'IIS': [r'IIS', r'Microsoft-IIS']
        }
    
    def comprehensive_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive web application scan.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dictionary containing scan results
        """
        if not HAS_REQUESTS:
            return {'error': 'requests library not available'}
        
        results = {
            'target': target_url,
            'timestamp': time.time(),
            'basic_info': {},
            'technologies': [],
            'security_headers': {},
            'ssl_info': {},
            'vulnerabilities': [],
            'discovered_paths': [],
            'forms': [],
            'cookies': [],
            'risk_score': 0
        }
        
        try:
            # Parse URL
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Basic information gathering
            results['basic_info'] = self._gather_basic_info(target_url)
            
            # Technology detection
            results['technologies'] = self._detect_technologies(target_url)
            
            # Security headers analysis
            results['security_headers'] = self._analyze_security_headers(target_url)
            
            # SSL/TLS analysis
            if parsed.scheme == 'https':
                results['ssl_info'] = self._analyze_ssl(parsed.netloc)
            
            # Check for common vulnerabilities
            results['vulnerabilities'] = self._check_common_vulnerabilities(target_url)
            
            # Directory and file discovery
            results['discovered_paths'] = self._discover_paths(base_url)
            
            # Form analysis
            if HAS_BS4:
                results['forms'] = self._analyze_forms(target_url)
            
            # Cookie analysis
            results['cookies'] = self._analyze_cookies(target_url)
            
            # Calculate risk score
            results['risk_score'] = self._calculate_risk_score(results)
            results['risk_level'] = self._get_risk_level(results['risk_score'])
            
        except Exception as e:
            self.logger.error(f"Web scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _gather_basic_info(self, url: str) -> Dict[str, Any]:
        """Gather basic information about the web application."""
        info = {
            'url': url,
            'status_code': None,
            'server': None,
            'powered_by': None,
            'content_type': None,
            'content_length': None,
            'response_time': None
        }
        
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=10, allow_redirects=True)
            info['response_time'] = time.time() - start_time
            
            info['status_code'] = response.status_code
            info['server'] = response.headers.get('Server', 'Unknown')
            info['powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
            info['content_type'] = response.headers.get('Content-Type', 'Unknown')
            info['content_length'] = len(response.content)
            
            # Check for redirects
            if response.history:
                info['redirects'] = [r.url for r in response.history]
                info['final_url'] = response.url
            
        except Exception as e:
            self.logger.error(f"Failed to gather basic info: {e}")
            info['error'] = str(e)
        
        return info
    
    def _detect_technologies(self, url: str) -> List[Dict[str, str]]:
        """Detect technologies used by the web application."""
        technologies = []
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            headers = response.headers
            
            # Check patterns in content
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.append({
                            'name': tech,
                            'confidence': 'high',
                            'detected_in': 'content'
                        })
                        break
            
            # Check headers
            header_text = ' '.join([f"{k}: {v}" for k, v in headers.items()])
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, header_text, re.IGNORECASE):
                        found = False
                        for t in technologies:
                            if t['name'] == tech:
                                found = True
                                break
                        if not found:
                            technologies.append({
                                'name': tech,
                                'confidence': 'medium',
                                'detected_in': 'headers'
                            })
                        break
            
            # Check for specific headers
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                technologies.append({
                    'name': powered_by,
                    'confidence': 'high',
                    'detected_in': 'X-Powered-By header'
                })
            
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
        
        return technologies
    
    def _analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers."""
        analysis = {
            'present': [],
            'missing': [],
            'misconfigured': [],
            'score': 0
        }
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            max_score = len(self.security_headers) * 10
            current_score = 0
            
            for header in self.security_headers:
                if header in headers:
                    analysis['present'].append({
                        'header': header,
                        'value': headers[header]
                    })
                    current_score += 10
                    
                    # Check for misconfigurations
                    if header == 'X-Frame-Options' and headers[header].upper() not in ['DENY', 'SAMEORIGIN']:
                        analysis['misconfigured'].append({
                            'header': header,
                            'issue': 'Should be DENY or SAMEORIGIN',
                            'current': headers[header]
                        })
                        current_score -= 5
                    
                else:
                    analysis['missing'].append(header)
            
            analysis['score'] = (current_score / max_score) * 100 if max_score > 0 else 0
            
        except Exception as e:
            self.logger.error(f"Security header analysis failed: {e}")
        
        return analysis
    
    def _analyze_ssl(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration."""
        ssl_info = {
            'enabled': False,
            'version': None,
            'cipher': None,
            'certificate': {},
            'vulnerabilities': []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info['enabled'] = True
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()
                    
                    # Get certificate details
                    cert = ssock.getpeercert()
                    ssl_info['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    # Check for vulnerabilities
                    if ssl_info['version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_info['vulnerabilities'].append({
                            'type': 'weak_protocol',
                            'description': f'Using outdated protocol: {ssl_info["version"]}',
                            'severity': 'high'
                        })
            
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _check_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Check for common web vulnerabilities."""
        vulnerabilities = []
        
        # Check for clickjacking
        try:
            response = self.session.get(url, timeout=10)
            if 'X-Frame-Options' not in response.headers:
                vulnerabilities.append({
                    'type': 'clickjacking',
                    'description': 'Missing X-Frame-Options header',
                    'severity': 'medium',
                    'remediation': 'Add X-Frame-Options header with value DENY or SAMEORIGIN'
                })
        except:
            pass
        
        # Check for exposed .git directory
        try:
            git_url = urljoin(url, '.git/HEAD')
            response = self.session.get(git_url, timeout=5)
            if response.status_code == 200 and 'ref:' in response.text:
                vulnerabilities.append({
                    'type': 'exposed_git',
                    'description': 'Git repository exposed',
                    'severity': 'high',
                    'url': git_url,
                    'remediation': 'Remove or protect .git directory'
                })
        except:
            pass
        
        # Check for exposed .env file
        try:
            env_url = urljoin(url, '.env')
            response = self.session.get(env_url, timeout=5)
            if response.status_code == 200 and '=' in response.text:
                vulnerabilities.append({
                    'type': 'exposed_env',
                    'description': 'Environment file exposed',
                    'severity': 'critical',
                    'url': env_url,
                    'remediation': 'Remove or protect .env file'
                })
        except:
            pass
        
        # Check for directory listing
        try:
            response = self.session.get(url, timeout=10)
            if 'Index of /' in response.text or '<title>Directory listing' in response.text:
                vulnerabilities.append({
                    'type': 'directory_listing',
                    'description': 'Directory listing enabled',
                    'severity': 'medium',
                    'remediation': 'Disable directory listing'
                })
        except:
            pass
        
        return vulnerabilities
    
    def _discover_paths(self, base_url: str, max_paths: int = 20) -> List[Dict[str, Any]]:
        """Discover accessible paths and files."""
        discovered = []
        checked = 0
        
        # Check common directories
        for dir_name in self.common_dirs[:max_paths//2]:
            if checked >= max_paths:
                break
            
            url = urljoin(base_url, dir_name)
            try:
                response = self.session.head(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 401, 403]:
                    discovered.append({
                        'path': f"/{dir_name}",
                        'type': 'directory',
                        'status_code': response.status_code,
                        'accessible': response.status_code == 200
                    })
                checked += 1
            except:
                pass
        
        # Check common files
        for file_name in self.common_files[:max_paths//2]:
            if checked >= max_paths:
                break
            
            url = urljoin(base_url, file_name)
            try:
                response = self.session.head(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    discovered.append({
                        'path': f"/{file_name}",
                        'type': 'file',
                        'status_code': response.status_code,
                        'accessible': response.status_code == 200
                    })
                checked += 1
            except:
                pass
        
        return discovered
    
    def _analyze_forms(self, url: str) -> List[Dict[str, Any]]:
        """Analyze forms on the page."""
        if not HAS_BS4:
            return []
        
        forms = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                    'has_csrf_token': False,
                    'potential_issues': []
                }
                
                # Analyze inputs
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'required': input_tag.get('required') is not None
                    }
                    
                    form_data['inputs'].append(input_info)
                    
                    # Check for CSRF token
                    if 'csrf' in input_info['name'].lower() or 'token' in input_info['name'].lower():
                        form_data['has_csrf_token'] = True
                    
                    # Check for password fields without HTTPS
                    if input_info['type'] == 'password' and not url.startswith('https'):
                        form_data['potential_issues'].append('Password field without HTTPS')
                
                # Check for missing CSRF protection
                if form_data['method'] == 'POST' and not form_data['has_csrf_token']:
                    form_data['potential_issues'].append('POST form without CSRF token')
                
                forms.append(form_data)
        
        except Exception as e:
            self.logger.error(f"Form analysis failed: {e}")
        
        return forms
    
    def _analyze_cookies(self, url: str) -> List[Dict[str, Any]]:
        """Analyze cookies set by the application."""
        cookies = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite'),
                    'issues': []
                }
                
                # Check for security issues
                if not cookie.secure and url.startswith('https'):
                    cookie_info['issues'].append('Cookie without Secure flag on HTTPS')
                
                if not cookie_info['httponly'] and 'session' in cookie.name.lower():
                    cookie_info['issues'].append('Session cookie without HttpOnly flag')
                
                if not cookie_info['samesite']:
                    cookie_info['issues'].append('Cookie without SameSite attribute')
                
                cookies.append(cookie_info)
        
        except Exception as e:
            self.logger.error(f"Cookie analysis failed: {e}")
        
        return cookies
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score for the web application."""
        score = 0.0
        
        # Factor in security headers
        if 'security_headers' in results:
            header_score = results['security_headers'].get('score', 0)
            score += (100 - header_score) * 0.3  # 30% weight
        
        # Factor in vulnerabilities
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                if vuln['severity'] == 'critical':
                    score += 20
                elif vuln['severity'] == 'high':
                    score += 15
                elif vuln['severity'] == 'medium':
                    score += 10
                elif vuln['severity'] == 'low':
                    score += 5
        
        # Factor in SSL issues
        if 'ssl_info' in results:
            if not results['ssl_info'].get('enabled'):
                score += 20  # No HTTPS
            elif results['ssl_info'].get('vulnerabilities'):
                score += len(results['ssl_info']['vulnerabilities']) * 10
        
        # Factor in cookie issues
        if 'cookies' in results:
            for cookie in results['cookies']:
                score += len(cookie.get('issues', [])) * 2
        
        # Factor in form issues
        if 'forms' in results:
            for form in results['forms']:
                score += len(form.get('potential_issues', [])) * 5
        
        return min(100, score)  # Cap at 100
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score."""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def export_scan_report(self, results: Dict[str, Any], 
                          filepath: str, format: str = 'html') -> None:
        """
        Export web scan report.
        
        Args:
            results: Scan results from comprehensive_scan
            filepath: Output file path
            format: Report format ('html', 'json')
        """
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        elif format == 'html':
            html = self._generate_html_report(results)
            with open(filepath, 'w') as f:
                f.write(html)
        
        self.logger.info(f"Web scan report exported to {filepath}")
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report for web scan results."""
        risk_color = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff8800',
            'MEDIUM': '#ffcc00',
            'LOW': '#00cc00',
            'MINIMAL': '#888888'
        }.get(results.get('risk_level', 'MINIMAL'), '#888888')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Web Application Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 3px; color: white; font-weight: bold; background: {risk_color}; }}
        .vuln {{ padding: 10px; margin: 10px 0; border-left: 4px solid #ff0000; background: #fff5f5; }}
        .tech {{ display: inline-block; padding: 3px 8px; margin: 2px; background: #e0e0e0; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Application Security Scan Report</h1>
        <p>Target: {results.get('target', 'Unknown')}</p>
        <p>Scan Date: {datetime.fromtimestamp(results.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Risk Assessment</h2>
        <p>Risk Level: <span class="risk-badge">{results.get('risk_level', 'Unknown')}</span></p>
        <p>Risk Score: {results.get('risk_score', 0):.1f}/100</p>
    </div>
"""
        
        # Technologies section
        if results.get('technologies'):
            html += """
    <div class="section">
        <h2>Detected Technologies</h2>
        <div>
"""
            for tech in results['technologies']:
                html += f'            <span class="tech">{tech["name"]}</span>\n'
            html += """        </div>
    </div>
"""
        
        # Vulnerabilities section
        if results.get('vulnerabilities'):
            html += """
    <div class="section">
        <h2>Vulnerabilities Found</h2>
"""
            for vuln in results['vulnerabilities']:
                html += f"""
        <div class="vuln">
            <strong>{vuln['type'].replace('_', ' ').title()}</strong> ({vuln['severity'].upper()})<br>
            {vuln['description']}<br>
            <small>Remediation: {vuln.get('remediation', 'N/A')}</small>
        </div>
"""
            html += "    </div>\n"
        
        # Security headers section
        if results.get('security_headers'):
            headers = results['security_headers']
            html += f"""
    <div class="section">
        <h2>Security Headers Analysis</h2>
        <p>Score: {headers.get('score', 0):.1f}%</p>
        <h3>Missing Headers:</h3>
        <ul>
"""
            for header in headers.get('missing', []):
                html += f"            <li>{header}</li>\n"
            html += """        </ul>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
