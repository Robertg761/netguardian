#!/usr/bin/env python3
"""
NetGuardian Sniffer Module
Provides packet capture and analysis functionality.

This module uses scapy to capture and analyze network packets in real-time,
providing detailed information about network traffic.
"""

import logging
import time
import threading
from typing import Optional, Dict, Any, List
import sys
import os

try:
    from scapy.all import (
        sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, 
        get_if_list, conf, Raw
    )
    # Disable scapy's verbose output
    conf.verb = 0
except ImportError:
    raise ImportError(
        "scapy is required for packet sniffing. Install with: pip install scapy"
    )


class PacketSniffer:
    """
    A class for capturing and analyzing network packets.
    
    This sniffer provides:
    - Real-time packet capture
    - Protocol analysis (TCP, UDP, ICMP, ARP, DNS)
    - Packet filtering
    - Traffic statistics
    """
    
    def __init__(self):
        """Initialize the PacketSniffer."""
        self.logger = logging.getLogger(__name__)
        self.packet_count = 0
        self.start_time = None
        self.stop_sniffing = False
        self.statistics = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'dns': 0,
            'other': 0,
            'total': 0
        }
    
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        try:
            return get_if_list()
        except Exception as e:
            self.logger.error(f"Failed to get interfaces: {e}")
            return []
    
    def validate_interface(self, interface: str) -> bool:
        """
        Validate if the specified interface exists.
        
        Args:
            interface: Interface name to validate
            
        Returns:
            True if interface exists, False otherwise
        """
        available_interfaces = self.get_available_interfaces()
        return interface in available_interfaces
    
    def start_sniffing(self, interface: str, count: int = 100, 
                      filter_expr: str = "") -> None:
        """
        Start packet capture on the specified interface.
        
        Args:
            interface: Network interface to capture on
            count: Number of packets to capture (0 = infinite)
            filter_expr: BPF filter expression
            
        Raises:
            ValueError: If interface is invalid
            RuntimeError: If sniffing fails to start
        """
        # Validate interface
        if not self.validate_interface(interface):
            available = ", ".join(self.get_available_interfaces())
            raise ValueError(
                f"Interface '{interface}' not found. "
                f"Available interfaces: {available}"
            )
        
        # Reset statistics
        self.packet_count = 0
        self.start_time = time.time()
        self.stop_sniffing = False
        for key in self.statistics:
            self.statistics[key] = 0
        
        self.logger.info(f"Starting packet capture on {interface}")
        if filter_expr:
            self.logger.info(f"Using filter: {filter_expr}")
        
        try:
            print(f"\nStarting packet capture on interface: {interface}")
            print(f"Capture count: {'Unlimited' if count == 0 else count}")
            if filter_expr:
                print(f"Filter: {filter_expr}")
            print("Press Ctrl+C to stop capture\n")
            
            print(f"{'Time':<12} {'Protocol':<8} {'Source':<18} {'Destination':<18} {'Info'}")
            print("-" * 80)
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=count,
                filter=filter_expr if filter_expr else None,
                stop_filter=lambda x: self.stop_sniffing
            )
            
        except Exception as e:
            error_msg = f"Packet capture failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        finally:
            self._print_statistics()
    
    def process_packet(self, packet) -> None:
        """
        Process each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            self.statistics['total'] += 1
            
            # Get current time
            current_time = time.strftime("%H:%M:%S")
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            # Update statistics
            protocol = packet_info['protocol'].lower()
            if protocol in self.statistics:
                self.statistics[protocol] += 1
            else:
                self.statistics['other'] += 1
            
            # Print packet information
            print(f"{current_time:<12} {packet_info['protocol']:<8} "
                  f"{packet_info['src']:<18} {packet_info['dst']:<18} "
                  f"{packet_info['info']}")
            
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Dict[str, str]:
        """
        Extract relevant information from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing packet information
        """
        info = {
            'protocol': 'Unknown',
            'src': 'Unknown',
            'dst': 'Unknown',
            'info': 'No additional info'
        }
        
        try:
            # Ethernet layer
            if Ether in packet:
                info['src'] = packet[Ether].src
                info['dst'] = packet[Ether].dst
            
            # IP layer
            if IP in packet:
                info['src'] = packet[IP].src
                info['dst'] = packet[IP].dst
                
                # TCP
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = self._get_tcp_flags(packet[TCP])
                    info['info'] = f"Ports: {src_port}→{dst_port} Flags: {flags}"
                    
                    # Check for HTTP traffic
                    if src_port == 80 or dst_port == 80:
                        info['info'] += " [HTTP]"
                    elif src_port == 443 or dst_port == 443:
                        info['info'] += " [HTTPS]"
                
                # UDP
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    info['info'] = f"Ports: {src_port}→{dst_port}"
                    
                    # DNS
                    if DNS in packet:
                        info['protocol'] = 'DNS'
                        if packet[DNS].qr == 0:  # Query
                            query_name = packet[DNS].qd.qname.decode('utf-8')
                            info['info'] = f"Query: {query_name}"
                        else:  # Response
                            info['info'] = "Response"
                
                # ICMP
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    info['info'] = f"Type: {icmp_type} Code: {icmp_code}"
            
            # ARP
            elif ARP in packet:
                info['protocol'] = 'ARP'
                info['src'] = packet[ARP].psrc
                info['dst'] = packet[ARP].pdst
                if packet[ARP].op == 1:  # Request
                    info['info'] = f"Who has {packet[ARP].pdst}?"
                elif packet[ARP].op == 2:  # Reply
                    info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
            
        except Exception as e:
            self.logger.debug(f"Error extracting packet info: {e}")
            info['info'] = "Error parsing packet"
        
        return info
    
    def _get_tcp_flags(self, tcp_packet) -> str:
        """
        Get TCP flags as a string.
        
        Args:
            tcp_packet: TCP packet layer
            
        Returns:
            String representation of TCP flags
        """
        flags = []
        
        if tcp_packet.flags.F: flags.append('FIN')
        if tcp_packet.flags.S: flags.append('SYN')
        if tcp_packet.flags.R: flags.append('RST')
        if tcp_packet.flags.P: flags.append('PSH')
        if tcp_packet.flags.A: flags.append('ACK')
        if tcp_packet.flags.U: flags.append('URG')
        if tcp_packet.flags.E: flags.append('ECE')
        if tcp_packet.flags.C: flags.append('CWR')
        
        return ','.join(flags) if flags else 'None'
    
    def _print_statistics(self) -> None:
        """Print capture statistics."""
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"\n{'='*50}")
            print("CAPTURE STATISTICS")
            print(f"{'='*50}")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Total packets: {self.statistics['total']}")
            print(f"Packets per second: {self.statistics['total']/duration:.2f}")
            print("\nProtocol breakdown:")
            for protocol, count in self.statistics.items():
                if count > 0 and protocol != 'total':
                    percentage = (count / self.statistics['total']) * 100
                    print(f"  {protocol.upper():<8}: {count:>6} ({percentage:>5.1f}%)")
    
    def stop_capture(self) -> None:
        """Stop the packet capture."""
        self.stop_sniffing = True
        self.logger.info("Stopping packet capture...")
    
    def capture_to_file(self, interface: str, filename: str, count: int = 100,
                       filter_expr: str = "") -> None:
        """
        Capture packets and save to a file.
        
        Args:
            interface: Network interface to capture on
            filename: Output filename (should end with .pcap)
            count: Number of packets to capture
            filter_expr: BPF filter expression
        """
        from scapy.all import wrpcap
        
        if not self.validate_interface(interface):
            available = ", ".join(self.get_available_interfaces())
            raise ValueError(
                f"Interface '{interface}' not found. "
                f"Available interfaces: {available}"
            )
        
        self.logger.info(f"Capturing {count} packets to {filename}")
        
        try:
            packets = sniff(
                iface=interface,
                count=count,
                filter=filter_expr if filter_expr else None
            )
            
            wrpcap(filename, packets)
            print(f"\nCaptured {len(packets)} packets to {filename}")
            
        except Exception as e:
            error_msg = f"File capture failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e


def main():
    """
    Main function for testing the sniffer module independently.
    """
    import argparse
    
    # Set up basic logging
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="NetGuardian Packet Sniffer")
    parser.add_argument('--interface', required=True, help='Network interface')
    parser.add_argument('--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('--filter', default='', help='Packet filter expression')
    parser.add_argument('--output', help='Output file (optional)')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces')
    
    args = parser.parse_args()
    
    sniffer = PacketSniffer()
    
    if args.list_interfaces:
        interfaces = sniffer.get_available_interfaces()
        print("Available network interfaces:")
        for interface in interfaces:
            print(f"  {interface}")
        sys.exit(0)
    
    try:
        if args.output:
            sniffer.capture_to_file(args.interface, args.output, args.count, args.filter)
        else:
            sniffer.start_sniffing(args.interface, args.count, args.filter)
            
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        sniffer.stop_capture()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
