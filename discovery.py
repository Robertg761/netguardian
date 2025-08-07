#!/usr/bin/env python3
"""
NetGuardian Discovery Module
Provides host discovery functionality using ARP scanning.

This module uses scapy to perform ARP scans which are efficient and less
detectable than traditional ping scans for local network discovery.
"""

import logging
import ipaddress
from typing import List, Dict, Optional
import re

try:
    from scapy.all import ARP, Ether, srp, conf
    # Disable scapy's verbose output
    conf.verb = 0
except ImportError:
    raise ImportError(
        "scapy is required for host discovery. Install with: pip install scapy"
    )


class HostDiscoverer:
    """
    A class for discovering live hosts on a network using ARP scanning.
    
    ARP scanning is used because it's:
    - Fast and efficient for local networks
    - Less likely to be detected by intrusion detection systems
    - Works even when ICMP is blocked
    """
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize the HostDiscoverer.
        
        Args:
            timeout: Timeout in seconds for ARP requests (default: 2.0)
        """
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def validate_network_range(self, target_range: str) -> bool:
        """
        Validate if the target range is a valid network CIDR notation.
        
        Args:
            target_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_network(target_range, strict=False)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def discover_hosts(self, target_range: str) -> List[Dict[str, str]]:
        """
        Discover live hosts on the specified network range using ARP scanning.
        
        Args:
            target_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            List of dictionaries containing IP and MAC addresses of discovered hosts
            
        Raises:
            ValueError: If the target range is invalid
            RuntimeError: If the ARP scan fails
        """
        # Validate input
        if not self.validate_network_range(target_range):
            raise ValueError(f"Invalid network range: {target_range}")
        
        self.logger.info(f"Starting ARP scan on {target_range}")
        
        try:
            # Create ARP request packet
            # We broadcast to ff:ff:ff:ff:ff:ff to reach all hosts
            arp_request = ARP(pdst=target_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send the packet and receive responses
            # srp() sends at layer 2 (Ethernet) and receives responses
            self.logger.debug(f"Sending ARP requests with timeout {self.timeout}s")
            answered_list = srp(
                arp_request_broadcast, 
                timeout=self.timeout, 
                verbose=False
            )[0]
            
            # Parse responses
            discovered_hosts = []
            for element in answered_list:
                # Each element is a tuple: (sent_packet, received_packet)
                received_packet = element[1]
                
                host_info = {
                    'ip': received_packet.psrc,  # Source IP from ARP response
                    'mac': received_packet.hwsrc  # Source MAC from ARP response
                }
                discovered_hosts.append(host_info)
                
                self.logger.debug(f"Discovered host: {host_info['ip']} ({host_info['mac']})")
            
            self.logger.info(f"Discovery completed. Found {len(discovered_hosts)} hosts")
            return discovered_hosts
            
        except Exception as e:
            error_msg = f"ARP scan failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    def discover_single_host(self, target_ip: str) -> Optional[Dict[str, str]]:
        """
        Discover a single host by IP address.
        
        Args:
            target_ip: IP address to check
            
        Returns:
            Dictionary with IP and MAC if host is alive, None otherwise
        """
        try:
            # Validate IP address
            ipaddress.ip_address(target_ip)
            
            # Use the main discovery method with /32 (single host) CIDR
            results = self.discover_hosts(f"{target_ip}/32")
            
            return results[0] if results else None
            
        except (ipaddress.AddressValueError, ValueError, RuntimeError):
            return None
    
    def get_network_info(self, target_range: str) -> Dict[str, str]:
        """
        Get information about the target network range.
        
        Args:
            target_range: Network range in CIDR notation
            
        Returns:
            Dictionary containing network information
        """
        try:
            network = ipaddress.ip_network(target_range, strict=False)
            
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'num_addresses': str(network.num_addresses),
                'is_private': str(network.is_private),
                'prefix_length': str(network.prefixlen)
            }
            
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid network range: {e}")


def main():
    """
    Main function for testing the discovery module independently.
    """
    import sys
    
    # Set up basic logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) != 2:
        print("Usage: python discovery.py <network_range>")
        print("Example: python discovery.py 192.168.1.0/24")
        sys.exit(1)
    
    target = sys.argv[1]
    
    try:
        discoverer = HostDiscoverer()
        
        # Show network information
        print(f"Network Information for {target}:")
        network_info = discoverer.get_network_info(target)
        for key, value in network_info.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print(f"\nStarting host discovery on {target}...")
        results = discoverer.discover_hosts(target)
        
        if results:
            print(f"\nDiscovered {len(results)} hosts:")
            print(f"{'IP Address':<15} {'MAC Address'}")
            print("-" * 35)
            for host in results:
                print(f"{host['ip']:<15} {host['mac']}")
        else:
            print("No hosts discovered.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
