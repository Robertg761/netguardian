#!/usr/bin/env python3
"""
NetGuardian Scanner Module
Provides port scanning and service detection functionality.

This module uses python-nmap to interface with the nmap tool for comprehensive
port scanning, service detection, and OS fingerprinting.
"""

import logging
import re
import subprocess
import ipaddress
from typing import Dict, List, Any, Optional
import sys
import os

try:
    import nmap
except ImportError:
    raise ImportError(
        "python-nmap is required for port scanning. Install with: pip install python-nmap"
    )


class PortScanner:
    """
    A class for performing port scans and service detection using nmap.
    
    This scanner provides:
    - TCP SYN scanning (stealthy and fast)
    - Service version detection
    - Operating system detection
    - Customizable port ranges
    """
    
    def __init__(self):
        """Initialize the PortScanner."""
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
        # Verify nmap is installed
        if not self._check_nmap_installation():
            raise RuntimeError(
                "nmap is not installed or not in PATH. "
                "Please install with: brew install nmap"
            )
    
    def _check_nmap_installation(self) -> bool:
        """
        Check if nmap is installed and accessible.
        
        Returns:
            True if nmap is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['nmap', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """
        Validate if the provided string is a valid IP address.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def _parse_port_range(self, port_range: str) -> str:
        """
        Parse and validate port range string.
        
        Args:
            port_range: Port range string (e.g., "1-1024", "80,443", "22")
            
        Returns:
            Validated port range string
            
        Raises:
            ValueError: If port range is invalid
        """
        # Remove spaces
        port_range = port_range.replace(' ', '')
        
        # Check for valid patterns
        patterns = [
            r'^\d+$',  # Single port: 80
            r'^\d+-\d+$',  # Range: 1-1024
            r'^(\d+,)*\d+$',  # List: 80,443,8080
            r'^(\d+-\d+,)*(\d+-\d+|\d+)$'  # Mixed: 1-100,443,8080-8090
        ]
        
        if any(re.match(pattern, port_range) for pattern in patterns):
            return port_range
        else:
            raise ValueError(f"Invalid port range format: {port_range}")
    
    def scan_ports(self, target_ip: str, port_range: str = "1-1024") -> Dict[str, Any]:
        """
        Perform a comprehensive port scan on the target.
        
        Args:
            target_ip: IP address to scan
            port_range: Port range to scan (default: "1-1024")
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            ValueError: If target IP or port range is invalid
            RuntimeError: If the scan fails
        """
        # Validate inputs
        if not self._validate_ip_address(target_ip):
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        try:
            validated_ports = self._parse_port_range(port_range)
        except ValueError as e:
            raise ValueError(str(e))
        
        self.logger.info(f"Starting port scan on {target_ip}:{validated_ports}")
        
        try:
            # Perform the scan
            # -sS: TCP SYN scan (stealthy)
            # -sV: Service version detection
            # -O: OS detection
            # -T4: Aggressive timing (faster)
            # --max-retries 1: Limit retries for faster scanning
            scan_args = f"-sS -sV -O -T4 --max-retries 1 -p {validated_ports}"
            
            self.logger.debug(f"Running nmap with arguments: {scan_args}")
            self.nm.scan(target_ip, arguments=scan_args)
            
            # Parse results
            results = self._parse_scan_results(target_ip)
            
            self.logger.info(f"Scan completed for {target_ip}")
            return results
            
        except Exception as e:
            error_msg = f"Port scan failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    def _parse_scan_results(self, target_ip: str) -> Dict[str, Any]:
        """
        Parse nmap scan results into a structured format.
        
        Args:
            target_ip: The scanned IP address
            
        Returns:
            Dictionary containing parsed scan results
        """
        results = {
            'host': target_ip,
            'status': 'unknown',
            'ports': [],
            'os': 'Unknown'
        }
        
        # Check if host was found in scan results
        if target_ip not in self.nm.all_hosts():
            results['status'] = 'down'
            return results
        
        # Get host information
        host_info = self.nm[target_ip]
        results['status'] = host_info.state()
        
        # Parse open ports
        if 'tcp' in host_info:
            for port, port_info in host_info['tcp'].items():
                if port_info['state'] == 'open':
                    port_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'service': port_info.get('name', 'unknown'),
                        'version': self._format_service_version(port_info)
                    }
                    results['ports'].append(port_data)
        
        # Parse OS detection results
        if 'osmatch' in host_info and host_info['osmatch']:
            # Get the most likely OS match
            best_match = max(
                host_info['osmatch'], 
                key=lambda x: int(x.get('accuracy', 0))
            )
            results['os'] = f"{best_match['name']} ({best_match['accuracy']}% accuracy)"
        
        return results
    
    def _format_service_version(self, port_info: Dict[str, Any]) -> str:
        """
        Format service version information.
        
        Args:
            port_info: Port information dictionary from nmap results
            
        Returns:
            Formatted version string
        """
        version_parts = []
        
        if port_info.get('product'):
            version_parts.append(port_info['product'])
        
        if port_info.get('version'):
            version_parts.append(port_info['version'])
        
        if port_info.get('extrainfo'):
            version_parts.append(f"({port_info['extrainfo']})")
        
        return ' '.join(version_parts) if version_parts else 'N/A'
    
    def quick_scan(self, target_ip: str) -> Dict[str, Any]:
        """
        Perform a quick scan of common ports.
        
        Args:
            target_ip: IP address to scan
            
        Returns:
            Dictionary containing scan results
        """
        # Common ports to scan quickly
        common_ports = "21,22,23,25,53,80,110,143,443,993,995,8080,8443"
        return self.scan_ports(target_ip, common_ports)
    
    def scan_top_ports(self, target_ip: str, top_ports: int = 100) -> Dict[str, Any]:
        """
        Scan the most common ports.
        
        Args:
            target_ip: IP address to scan
            top_ports: Number of top ports to scan (default: 100)
            
        Returns:
            Dictionary containing scan results
        """
        if not self._validate_ip_address(target_ip):
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        self.logger.info(f"Scanning top {top_ports} ports on {target_ip}")
        
        try:
            # Use nmap's --top-ports option
            scan_args = f"-sS -sV --top-ports {top_ports} -T4"
            self.nm.scan(target_ip, arguments=scan_args)
            
            return self._parse_scan_results(target_ip)
            
        except Exception as e:
            error_msg = f"Top ports scan failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    def get_nmap_version(self) -> str:
        """
        Get the version of nmap being used.
        
        Returns:
            Nmap version string
        """
        try:
            return self.nm.nmap_version()
        except Exception:
            return "Unknown"


def main():
    """
    Main function for testing the scanner module independently.
    """
    import sys
    
    # Set up basic logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_ip> [port_range]")
        print("Example: python scanner.py 192.168.1.1")
        print("Example: python scanner.py 192.168.1.1 1-100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    
    try:
        scanner = PortScanner()
        print(f"Using nmap version: {scanner.get_nmap_version()}")
        print(f"Starting scan on {target_ip}...")
        
        results = scanner.scan_ports(target_ip, port_range)
        
        # Display results
        print(f"\nScan Results for {target_ip}:")
        print(f"Host Status: {results['status']}")
        
        if results['os'] != 'Unknown':
            print(f"Operating System: {results['os']}")
        
        if results['ports']:
            print(f"\nOpen Ports ({len(results['ports'])} found):")
            print(f"{'Port':<8} {'Service':<15} {'Version'}")
            print("-" * 50)
            
            for port in results['ports']:
                print(f"{port['port']:<8} {port['service']:<15} {port['version']}")
        else:
            print("\nNo open ports found.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
