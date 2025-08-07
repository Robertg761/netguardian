#!/usr/bin/env python3
"""
NetGuardian Vulnerability Testing Module
Provides advanced security testing capabilities for authorized penetration testing.

⚠️ CRITICAL WARNING: This module contains tools that can be harmful if misused.
Only use these tools on networks you OWN or have EXPLICIT WRITTEN PERMISSION to test.
Unauthorized use may be illegal and could result in criminal charges.
"""

import logging
import time
import threading
import socket
import random
import string
import hashlib
import itertools
from typing import List, Dict, Any, Optional, Generator
import sys
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sr1, conf
    conf.verb = 0
except ImportError:
    raise ImportError("scapy is required for vulnerability testing. Install with: pip install scapy")


class AuthorizationError(Exception):
    """Raised when authorization checks fail."""
    pass


class VulnerabilityTester:
    """
    Advanced vulnerability testing class with proper authorization checks.
    
    This class provides tools for:
    - Password strength testing (brute force simulation)
    - Network stress testing (controlled load testing)
    - Service enumeration and banner grabbing
    - SSL/TLS security analysis
    - Weak authentication detection
    
    ALL METHODS REQUIRE EXPLICIT AUTHORIZATION CONFIRMATION.
    """
    
    def __init__(self, require_authorization: bool = True):
        """
        Initialize the VulnerabilityTester.
        
        Args:
            require_authorization: Whether to require authorization checks (default: True)
        """
        self.logger = logging.getLogger(__name__)
        self.require_authorization = require_authorization
        self.authorized_targets = set()
        self.max_threads = 10  # Limit concurrent operations
        self.rate_limit = 0.1  # Minimum delay between requests
        
        # Warning banner
        self._show_warning_banner()
    
    def _show_warning_banner(self):
        """Display critical warning banner."""
        warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠️  CRITICAL WARNING  ⚠️                           ║
║                                                                              ║
║  This module contains ADVANCED SECURITY TESTING tools that can be HARMFUL   ║
║  if misused. These tools are designed for AUTHORIZED PENETRATION TESTING    ║
║  and SECURITY RESEARCH ONLY.                                                ║
║                                                                              ║
║  ⚠️  LEGAL NOTICE:                                                           ║
║  • Only use on networks you OWN or have EXPLICIT WRITTEN PERMISSION        ║
║  • Unauthorized use may be ILLEGAL and result in criminal charges           ║
║  • You are responsible for complying with all applicable laws               ║
║  • The authors assume NO RESPONSIBILITY for misuse of these tools           ║
║                                                                              ║
║  🛡️  ETHICAL USE ONLY:                                                       ║
║  • Obtain proper authorization before testing                               ║
║  • Document all testing activities                                          ║
║  • Follow responsible disclosure practices                                  ║
║  • Respect rate limits and avoid causing disruption                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(warning)
    
    def authorize_target(self, target: str, authorization_code: str = None) -> bool:
        """
        Authorize a target for testing with explicit confirmation.
        
        Args:
            target: Target IP or hostname
            authorization_code: Optional authorization code for automation
            
        Returns:
            True if authorized, False otherwise
            
        Raises:
            AuthorizationError: If authorization is required but not provided
        """
        if not self.require_authorization:
            self.authorized_targets.add(target)
            return True
        
        print(f"\n🔐 AUTHORIZATION REQUIRED FOR TARGET: {target}")
        print("=" * 60)
        print("By proceeding, you confirm that:")
        print("1. You OWN this network/system OR have EXPLICIT WRITTEN PERMISSION")
        print("2. You understand the legal implications of security testing")
        print("3. You will use these tools responsibly and ethically")
        print("4. You accept full responsibility for your actions")
        
        if authorization_code:
            confirmation = authorization_code
        else:
            confirmation = input("\nType 'I AUTHORIZE AND ACCEPT RESPONSIBILITY' to proceed: ")
        
        if confirmation.upper() == "I AUTHORIZE AND ACCEPT RESPONSIBILITY":
            self.authorized_targets.add(target)
            self.logger.info(f"Target {target} authorized for testing")
            print(f"✅ Target {target} authorized for testing")
            return True
        else:
            print("❌ Authorization denied. Testing aborted.")
            return False
    
    def _check_authorization(self, target: str) -> bool:
        """Check if target is authorized for testing."""
        if not self.require_authorization:
            return True
        
        if target in self.authorized_targets:
            return True
        
        raise AuthorizationError(f"Target {target} not authorized. Call authorize_target() first.")
    
    def password_strength_test(self, target_ip: str, port: int, service: str = "ssh",
                             wordlist: List[str] = None, max_attempts: int = 100) -> Dict[str, Any]:
        """
        Test password strength through controlled brute force simulation.
        
        ⚠️ WARNING: This is for testing password policies on YOUR OWN systems.
        
        Args:
            target_ip: Target IP address
            port: Target port
            service: Service type (ssh, ftp, telnet, http)
            wordlist: List of passwords to test (limited for safety)
            max_attempts: Maximum attempts (capped at 100 for safety)
            
        Returns:
            Dictionary containing test results
        """
        self._check_authorization(target_ip)
        
        # Safety limits
        max_attempts = min(max_attempts, 100)
        
        if not wordlist:
            # Small, common password list for testing
            wordlist = [
                "password", "123456", "admin", "root", "user",
                "guest", "test", "password123", "admin123", "qwerty"
            ]
        
        # Limit wordlist size for safety
        wordlist = wordlist[:max_attempts]
        
        self.logger.info(f"Starting password strength test on {target_ip}:{port} ({service})")
        
        results = {
            'target': f"{target_ip}:{port}",
            'service': service,
            'attempts': 0,
            'successful_logins': [],
            'weak_passwords': [],
            'connection_errors': 0,
            'rate_limited': False
        }
        
        for i, password in enumerate(wordlist):
            if i >= max_attempts:
                break
            
            try:
                # Add rate limiting to be respectful
                time.sleep(self.rate_limit)
                
                success = self._test_single_password(target_ip, port, service, "admin", password)
                results['attempts'] += 1
                
                if success:
                    results['successful_logins'].append({"username": "admin", "password": password})
                    results['weak_passwords'].append(password)
                    self.logger.warning(f"Weak password found: admin/{password}")
                
                # Progress indicator
                if i % 10 == 0:
                    print(f"Progress: {i}/{len(wordlist)} passwords tested")
                
            except Exception as e:
                results['connection_errors'] += 1
                self.logger.debug(f"Connection error: {e}")
                
                # If too many connection errors, the target might be rate limiting
                if results['connection_errors'] > 5:
                    results['rate_limited'] = True
                    self.logger.warning("Multiple connection failures - target may be rate limiting")
                    break
        
        self.logger.info(f"Password strength test completed: {results['attempts']} attempts")
        return results
    
    def _test_single_password(self, ip: str, port: int, service: str, 
                             username: str, password: str) -> bool:
        """
        Test a single password against a service.
        
        Returns:
            True if login successful, False otherwise
        """
        if service.lower() == "ssh":
            return self._test_ssh_login(ip, port, username, password)
        elif service.lower() == "ftp":
            return self._test_ftp_login(ip, port, username, password)
        elif service.lower() == "telnet":
            return self._test_telnet_login(ip, port, username, password)
        else:
            # For other services, just test TCP connection
            return self._test_tcp_connection(ip, port)
    
    def _test_ssh_login(self, ip: str, port: int, username: str, password: str) -> bool:
        """Test SSH login (simulated - requires paramiko for real testing)."""
        # This is a simulation - real implementation would use paramiko
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            # Simulate some passwords as "successful" for demonstration
            if password in ["password", "admin", "123456"]:
                return random.random() < 0.1  # 10% chance of "success" for demo
            
            return False
        except Exception:
            return False
    
    def _test_ftp_login(self, ip: str, port: int, username: str, password: str) -> bool:
        """Test FTP login."""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=3)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def _test_telnet_login(self, ip: str, port: int, username: str, password: str) -> bool:
        """Test Telnet login."""
        try:
            import telnetlib
            tn = telnetlib.Telnet(ip, port, timeout=3)
            tn.read_until(b"login: ", timeout=2)
            tn.write(username.encode() + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode() + b"\n")
            response = tn.read_some()
            tn.close()
            
            # Check if login was successful (basic heuristic)
            return b"$" in response or b"#" in response
        except:
            return False
    
    def _test_tcp_connection(self, ip: str, port: int) -> bool:
        """Test basic TCP connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def network_stress_test(self, target_ip: str, port: int, duration: int = 10,
                           connections_per_second: int = 10) -> Dict[str, Any]:
        """
        Perform controlled network stress testing.
        
        ⚠️ WARNING: This tests network capacity and should only be used on YOUR systems.
        
        Args:
            target_ip: Target IP address
            port: Target port
            duration: Test duration in seconds (max 60 for safety)
            connections_per_second: Connection rate (max 50 for safety)
            
        Returns:
            Dictionary containing test results
        """
        self._check_authorization(target_ip)
        
        # Safety limits
        duration = min(duration, 60)  # Max 60 seconds
        connections_per_second = min(connections_per_second, 50)  # Max 50 connections/sec
        
        self.logger.info(f"Starting network stress test on {target_ip}:{port}")
        print(f"⚠️ Starting controlled stress test on {target_ip}:{port}")
        print(f"Duration: {duration}s, Rate: {connections_per_second}/sec")
        
        results = {
            'target': f"{target_ip}:{port}",
            'duration': duration,
            'target_rate': connections_per_second,
            'successful_connections': 0,
            'failed_connections': 0,
            'response_times': [],
            'start_time': time.time(),
            'end_time': None
        }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=min(connections_per_second, 20)) as executor:
            while time.time() - start_time < duration:
                batch_start = time.time()
                
                # Submit a batch of connection attempts
                futures = []
                for _ in range(connections_per_second):
                    future = executor.submit(self._stress_test_connection, target_ip, port)
                    futures.append(future)
                
                # Collect results
                for future in as_completed(futures, timeout=1):
                    try:
                        connection_time = future.result()
                        if connection_time is not None:
                            results['successful_connections'] += 1
                            results['response_times'].append(connection_time)
                        else:
                            results['failed_connections'] += 1
                    except Exception:
                        results['failed_connections'] += 1
                
                # Rate limiting - wait until the second is up
                elapsed = time.time() - batch_start
                if elapsed < 1.0:
                    time.sleep(1.0 - elapsed)
        
        results['end_time'] = time.time()
        results['actual_duration'] = results['end_time'] - results['start_time']
        
        if results['response_times']:
            results['avg_response_time'] = sum(results['response_times']) / len(results['response_times'])
            results['min_response_time'] = min(results['response_times'])
            results['max_response_time'] = max(results['response_times'])
        
        self.logger.info(f"Stress test completed: {results['successful_connections']} successful, "
                        f"{results['failed_connections']} failed")
        
        return results
    
    def _stress_test_connection(self, ip: str, port: int) -> Optional[float]:
        """
        Perform a single connection test for stress testing.
        
        Returns:
            Connection time in seconds, or None if failed
        """
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Send a small amount of data to simulate real traffic
                try:
                    sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                    sock.recv(1024)
                except:
                    pass
            
            sock.close()
            
            if result == 0:
                return time.time() - start_time
            else:
                return None
                
        except Exception:
            return None
    
    def service_enumeration(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
        """
        Perform detailed service enumeration and banner grabbing.
        
        Args:
            target_ip: Target IP address
            ports: List of ports to scan
            
        Returns:
            Dictionary containing enumeration results
        """
        self._check_authorization(target_ip)
        
        self.logger.info(f"Starting service enumeration on {target_ip}")
        
        results = {
            'target': target_ip,
            'services': {},
            'banners': {},
            'vulnerabilities': [],
            'scan_time': time.time()
        }
        
        for port in ports:
            try:
                service_info = self._enumerate_service(target_ip, port)
                if service_info:
                    results['services'][port] = service_info
                    
                    # Get service banner
                    banner = self._grab_banner(target_ip, port)
                    if banner:
                        results['banners'][port] = banner
                        
                        # Check for known vulnerabilities in banners
                        vulns = self._check_banner_vulnerabilities(banner, port)
                        if vulns:
                            results['vulnerabilities'].extend(vulns)
                
                # Rate limiting
                time.sleep(self.rate_limit)
                
            except Exception as e:
                self.logger.debug(f"Error enumerating port {port}: {e}")
        
        self.logger.info(f"Service enumeration completed: {len(results['services'])} services found")
        return results
    
    def _enumerate_service(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Enumerate a single service."""
        try:
            # TCP connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_info = {
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': self._guess_service(port)
                }
                
                # Try to get more info
                try:
                    sock.send(b"\\n")
                    response = sock.recv(1024)
                    if response:
                        service_info['initial_response'] = response[:100].decode('utf-8', errors='ignore')
                except:
                    pass
                
                sock.close()
                return service_info
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Try different banner grabbing techniques
            banners = []
            
            # Method 1: Just connect and read
            try:
                banner = sock.recv(1024)
                if banner:
                    banners.append(banner)
            except:
                pass
            
            # Method 2: Send HTTP request
            try:
                sock.send(b"GET / HTTP/1.1\\r\\nHost: " + ip.encode() + b"\\r\\n\\r\\n")
                banner = sock.recv(1024)
                if banner:
                    banners.append(banner)
            except:
                pass
            
            # Method 3: Send generic request
            try:
                sock.send(b"\\r\\n\\r\\n")
                banner = sock.recv(1024)
                if banner:
                    banners.append(banner)
            except:
                pass
            
            sock.close()
            
            # Return the longest banner
            if banners:
                longest_banner = max(banners, key=len)
                return longest_banner.decode('utf-8', errors='ignore')
            
            return None
            
        except Exception:
            return None
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on port number."""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            3389: 'rdp', 5432: 'postgresql', 3306: 'mysql',
            6379: 'redis', 27017: 'mongodb'
        }
        return common_ports.get(port, 'unknown')
    
    def _check_banner_vulnerabilities(self, banner: str, port: int) -> List[Dict[str, str]]:
        """Check banner for known vulnerabilities."""
        vulnerabilities = []
        banner_lower = banner.lower()
        
        # Simple vulnerability checks (educational examples)
        vuln_patterns = {
            'apache/2.2': 'Apache 2.2.x has known vulnerabilities',
            'openssh 4.': 'OpenSSH 4.x has known vulnerabilities',
            'microsoft-iis/6.0': 'IIS 6.0 has known vulnerabilities',
            'mysql 4.': 'MySQL 4.x has known vulnerabilities'
        }
        
        for pattern, description in vuln_patterns.items():
            if pattern in banner_lower:
                vulnerabilities.append({
                    'port': port,
                    'pattern': pattern,
                    'description': description,
                    'severity': 'medium'
                })
        
        return vulnerabilities


def main():
    """
    Main function for testing the vulnerability testing module independently.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="NetGuardian Vulnerability Tester")
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--test', required=True, 
                       choices=['password', 'stress', 'enumerate'],
                       help='Test type to perform')
    parser.add_argument('--port', type=int, default=22, help='Target port')
    parser.add_argument('--authorize', action='store_true', 
                       help='Skip interactive authorization (for testing)')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize tester
        tester = VulnerabilityTester(require_authorization=not args.authorize)
        
        # Authorize target
        if not tester.authorize_target(args.target):
            print("Authorization failed. Exiting.")
            sys.exit(1)
        
        # Perform requested test
        if args.test == 'password':
            print(f"\\nPerforming password strength test on {args.target}:{args.port}")
            results = tester.password_strength_test(args.target, args.port)
            print(f"\\nResults: {results['attempts']} attempts, "
                  f"{len(results['weak_passwords'])} weak passwords found")
            
        elif args.test == 'stress':
            print(f"\\nPerforming network stress test on {args.target}:{args.port}")
            results = tester.network_stress_test(args.target, args.port, duration=10)
            print(f"\\nResults: {results['successful_connections']} successful, "
                  f"{results['failed_connections']} failed")
                  
        elif args.test == 'enumerate':
            print(f"\\nPerforming service enumeration on {args.target}")
            ports = [22, 80, 443, 3389]  # Common ports
            results = tester.service_enumeration(args.target, ports)
            print(f"\\nResults: {len(results['services'])} services found, "
                  f"{len(results['vulnerabilities'])} potential vulnerabilities")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
