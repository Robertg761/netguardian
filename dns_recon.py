#!/usr/bin/env python3
"""
NetGuardian DNS Reconnaissance Module
Provides comprehensive DNS analysis and enumeration capabilities.
"""

import logging
import socket
import subprocess
import time
from typing import List, Dict, Any, Optional, Set
import concurrent.futures
import re
import json

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("Warning: dnspython not available. Install with: pip install dnspython")

class DNSRecon:
    """
    A class for comprehensive DNS reconnaissance and analysis.
    """
    
    def __init__(self):
        """Initialize the DNSRecon module."""
        self.logger = logging.getLogger(__name__)
        self.resolver = dns.resolver.Resolver() if HAS_DNSPYTHON else None
        
        # Common subdomains for enumeration
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'vpn', 'admin', 'test', 'portal', 'dev', 'staging', 'api', 'app', 'mobile',
            'blog', 'forum', 'shop', 'store', 'download', 'media', 'news', 'support',
            'help', 'login', 'register', 'secure', 'ssl', 'cpanel', 'whm', 'webdisk',
            'remote', 'server', 'ns', 'mail2', 'smtp2', 'pop3', 'imap', 'cloud', 'git',
            'svn', 'jira', 'confluence', 'wiki', 'jenkins', 'gitlab', 'github', 'docker',
            'k8s', 'kubernetes', 'elastic', 'kibana', 'grafana', 'prometheus', 'monitor',
            'backup', 'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'ldap',
            'ad', 'dc', 'exchange', 'owa', 'autodiscover', 'lyncdiscover', 'sip'
        ]
        
        # DNS record types to query
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
        
    def perform_dns_lookup(self, domain: str, record_type: str = 'A') -> List[str]:
        """
        Perform DNS lookup for a specific record type.
        
        Args:
            domain: Domain name to query
            record_type: DNS record type (A, AAAA, MX, NS, etc.)
            
        Returns:
            List of results
        """
        results = []
        
        if HAS_DNSPYTHON:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    results.append(str(rdata))
            except Exception as e:
                self.logger.debug(f"DNS lookup failed for {domain} ({record_type}): {e}")
        else:
            # Fallback to system tools
            try:
                if record_type == 'A':
                    result = socket.gethostbyname(domain)
                    results.append(result)
                else:
                    # Use dig or nslookup
                    output = subprocess.check_output(
                        ['dig', '+short', domain, record_type],
                        text=True,
                        timeout=5
                    )
                    results = [line.strip() for line in output.splitlines() if line.strip()]
            except Exception as e:
                self.logger.debug(f"System DNS lookup failed: {e}")
        
        return results
    
    def comprehensive_dns_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive DNS analysis on a domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing all DNS information
        """
        self.logger.info(f"Starting comprehensive DNS analysis for {domain}")
        
        results = {
            'domain': domain,
            'timestamp': time.time(),
            'records': {},
            'subdomains': [],
            'zone_transfer': None,
            'dnssec': False,
            'nameservers': [],
            'mail_servers': [],
            'txt_records': [],
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'cname_chains': {},
            'srv_records': [],
            'wildcard': False,
            'dns_server_versions': {}
        }
        
        # Query all record types
        for record_type in self.record_types:
            records = self.perform_dns_lookup(domain, record_type)
            if records:
                results['records'][record_type] = records
                
                # Parse specific record types
                if record_type == 'A':
                    results['ipv4_addresses'] = records
                elif record_type == 'AAAA':
                    results['ipv6_addresses'] = records
                elif record_type == 'NS':
                    results['nameservers'] = records
                elif record_type == 'MX':
                    results['mail_servers'] = records
                elif record_type == 'TXT':
                    results['txt_records'] = records
                elif record_type == 'SRV':
                    results['srv_records'] = records
        
        # Check for wildcard DNS
        results['wildcard'] = self._check_wildcard_dns(domain)
        
        # Enumerate subdomains
        results['subdomains'] = self.enumerate_subdomains(domain, wordlist=self.common_subdomains[:20])
        
        # Try zone transfer
        results['zone_transfer'] = self._attempt_zone_transfer(domain)
        
        # Check DNSSEC
        results['dnssec'] = self._check_dnssec(domain)
        
        # Get DNS server versions
        for ns in results['nameservers']:
            version = self._get_dns_server_version(ns)
            if version:
                results['dns_server_versions'][ns] = version
        
        # Reverse DNS lookups
        results['reverse_dns'] = {}
        for ip in results['ipv4_addresses'][:5]:  # Limit to first 5
            hostname = self.reverse_dns_lookup(ip)
            if hostname:
                results['reverse_dns'][ip] = hostname
        
        return results
    
    def enumerate_subdomains(self, domain: str, wordlist: List[str] = None,
                           max_threads: int = 10) -> List[Dict[str, str]]:
        """
        Enumerate subdomains using a wordlist.
        
        Args:
            domain: Base domain
            wordlist: List of subdomain names to try
            max_threads: Maximum concurrent threads
            
        Returns:
            List of discovered subdomains with their IPs
        """
        if not wordlist:
            wordlist = self.common_subdomains[:30]  # Use top 30 common subdomains
        
        discovered = []
        
        def check_subdomain(subdomain: str) -> Optional[Dict[str, str]]:
            full_domain = f"{subdomain}.{domain}"
            ips = self.perform_dns_lookup(full_domain, 'A')
            if ips:
                return {'subdomain': full_domain, 'ips': ips}
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
                    self.logger.debug(f"Found subdomain: {result['subdomain']}")
        
        return discovered
    
    def reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup on an IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Hostname if found, None otherwise
        """
        try:
            if HAS_DNSPYTHON:
                rev_name = dns.reversename.from_address(ip_address)
                answers = self.resolver.resolve(rev_name, 'PTR')
                for rdata in answers:
                    return str(rdata).rstrip('.')
            else:
                # Fallback to socket
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                return hostname
        except Exception as e:
            self.logger.debug(f"Reverse DNS lookup failed for {ip_address}: {e}")
            return None
    
    def _check_wildcard_dns(self, domain: str) -> bool:
        """Check if domain has wildcard DNS enabled."""
        # Test with random subdomain
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
        test_domain = f"{random_sub}.{domain}"
        
        results = self.perform_dns_lookup(test_domain, 'A')
        return len(results) > 0
    
    def _attempt_zone_transfer(self, domain: str) -> Optional[List[str]]:
        """
        Attempt DNS zone transfer (AXFR).
        
        Args:
            domain: Target domain
            
        Returns:
            Zone records if successful, None otherwise
        """
        if not HAS_DNSPYTHON:
            return None
        
        zone_records = []
        
        try:
            # Get nameservers
            ns_records = self.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_str = str(ns).rstrip('.')
                try:
                    # Get NS IP
                    ns_ip = self.resolver.resolve(ns_str, 'A')[0]
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(str(ns_ip), domain, timeout=5)
                    )
                    
                    # Parse zone records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                record = f"{name}.{domain} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}"
                                zone_records.append(record)
                    
                    self.logger.info(f"Zone transfer successful from {ns_str}")
                    return zone_records
                    
                except Exception as e:
                    self.logger.debug(f"Zone transfer failed from {ns_str}: {e}")
                    continue
        
        except Exception as e:
            self.logger.debug(f"Zone transfer attempt failed: {e}")
        
        return None if not zone_records else zone_records
    
    def _check_dnssec(self, domain: str) -> bool:
        """Check if domain has DNSSEC enabled."""
        if not HAS_DNSPYTHON:
            return False
        
        try:
            # Query for DNSKEY records
            answers = self.resolver.resolve(domain, 'DNSKEY')
            return len(answers) > 0
        except:
            return False
    
    def _get_dns_server_version(self, nameserver: str) -> Optional[str]:
        """
        Try to get DNS server version using version.bind query.
        
        Args:
            nameserver: DNS server hostname
            
        Returns:
            Version string if found
        """
        if not HAS_DNSPYTHON:
            return None
        
        try:
            # Clean up nameserver name
            ns = nameserver.rstrip('.')
            
            # Create a version.bind query
            query = dns.message.make_query('version.bind', 'TXT', 'CH')
            
            # Get nameserver IP
            ns_ip = self.resolver.resolve(ns, 'A')[0]
            
            # Send query
            response = dns.query.udp(query, str(ns_ip), timeout=2)
            
            # Parse response
            for rrset in response.answer:
                for rdata in rrset:
                    if hasattr(rdata, 'strings'):
                        return rdata.strings[0].decode('utf-8')
        except Exception as e:
            self.logger.debug(f"Failed to get DNS server version for {nameserver}: {e}")
        
        return None
    
    def find_dns_records_by_ip(self, ip_address: str, domains: List[str]) -> List[str]:
        """
        Find all domains pointing to a specific IP address.
        
        Args:
            ip_address: Target IP address
            domains: List of domains to check
            
        Returns:
            List of domains pointing to the IP
        """
        matching_domains = []
        
        for domain in domains:
            ips = self.perform_dns_lookup(domain, 'A')
            if ip_address in ips:
                matching_domains.append(domain)
        
        return matching_domains
    
    def dns_cache_snooping(self, nameserver: str, domains: List[str]) -> Dict[str, bool]:
        """
        Perform DNS cache snooping to check if domains are cached.
        
        Args:
            nameserver: Target DNS server
            domains: List of domains to check
            
        Returns:
            Dictionary of domain -> cached status
        """
        if not HAS_DNSPYTHON:
            return {}
        
        results = {}
        
        try:
            # Get nameserver IP
            ns_ip = socket.gethostbyname(nameserver)
            
            for domain in domains:
                try:
                    # Create non-recursive query
                    query = dns.message.make_query(domain, 'A')
                    query.flags = 0  # Remove recursion desired flag
                    
                    # Send query
                    response = dns.query.udp(query, ns_ip, timeout=2)
                    
                    # Check if we got an answer (means it was cached)
                    results[domain] = len(response.answer) > 0
                    
                except Exception:
                    results[domain] = False
        
        except Exception as e:
            self.logger.debug(f"DNS cache snooping failed: {e}")
        
        return results
    
    def export_dns_report(self, analysis_results: Dict[str, Any], 
                         filepath: str, format: str = 'json') -> None:
        """
        Export DNS analysis results to file.
        
        Args:
            analysis_results: Results from comprehensive_dns_analysis
            filepath: Output file path
            format: Output format ('json', 'txt', 'csv')
        """
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
        
        elif format == 'txt':
            with open(filepath, 'w') as f:
                f.write(f"DNS Analysis Report for {analysis_results['domain']}\n")
                f.write("=" * 60 + "\n\n")
                
                # Write records
                for record_type, records in analysis_results['records'].items():
                    f.write(f"{record_type} Records:\n")
                    for record in records:
                        f.write(f"  {record}\n")
                    f.write("\n")
                
                # Write subdomains
                if analysis_results['subdomains']:
                    f.write("Discovered Subdomains:\n")
                    for sub in analysis_results['subdomains']:
                        f.write(f"  {sub['subdomain']}: {', '.join(sub['ips'])}\n")
                    f.write("\n")
                
                # Write other information
                f.write(f"DNSSEC Enabled: {analysis_results['dnssec']}\n")
                f.write(f"Wildcard DNS: {analysis_results['wildcard']}\n")
                
                if analysis_results['zone_transfer']:
                    f.write(f"\nZone Transfer Possible: Yes\n")
                    f.write(f"Records obtained: {len(analysis_results['zone_transfer'])}\n")
        
        self.logger.info(f"DNS report exported to {filepath}")
