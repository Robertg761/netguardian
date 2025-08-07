#!/usr/bin/env python3
"""
NetGuardian - A Modular Network Analysis Suite
Main entry point for the network analysis tool.

Usage:
    python main.py discover --target 192.168.1.0/24
    python main.py scan --target 192.168.1.1 --ports 1-1024
    python main.py sniff --interface en0 --count 100
"""

import argparse
import sys
import logging
from typing import List, Dict, Any

# Import our modules
try:
    from discovery import HostDiscoverer
    from scanner import PortScanner
    from sniffer import PacketSniffer
    from vuln_testing import VulnerabilityTester
    from advanced_testing import EthicalTester
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are present in the same directory.")
    sys.exit(1)


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def print_discovery_results(results: List[Dict[str, str]]) -> None:
    """Print host discovery results in a formatted table."""
    if not results:
        print("No hosts discovered.")
        return
    
    print("\n" + "="*50)
    print("DISCOVERED HOSTS")
    print("="*50)
    print(f"{'IP Address':<15} {'MAC Address':<18}")
    print("-" * 35)
    
    for host in results:
        ip = host.get('ip', 'Unknown')
        mac = host.get('mac', 'Unknown')
        print(f"{ip:<15} {mac:<18}")
    
    print(f"\nTotal hosts discovered: {len(results)}")


def print_scan_results(results: Dict[str, Any]) -> None:
    """Print port scan results in a formatted display."""
    if not results:
        print("No scan results available.")
        return
    
    print("\n" + "="*60)
    print(f"SCAN RESULTS FOR {results.get('host', 'Unknown')}")
    print("="*60)
    
    status = results.get('status', 'Unknown')
    print(f"Host Status: {status}")
    
    # OS Detection
    os_info = results.get('os', 'Unknown')
    if os_info and os_info != 'Unknown':
        print(f"Operating System: {os_info}")
    
    # Open Ports
    ports = results.get('ports', [])
    if ports:
        print(f"\nOpen Ports ({len(ports)} found):")
        print(f"{'Port':<8} {'Protocol':<10} {'Service':<15} {'Version'}")
        print("-" * 55)
        
        for port in ports:
            port_num = port.get('port', 'N/A')
            protocol = port.get('protocol', 'N/A')
            service = port.get('service', 'Unknown')
            version = port.get('version', 'N/A')
            print(f"{port_num:<8} {protocol:<10} {service:<15} {version}")
    else:
        print("\nNo open ports found.")


def handle_discover_command(args) -> None:
    """Handle the discover command."""
    try:
        print(f"Starting host discovery on {args.target}...")
        discoverer = HostDiscoverer()
        results = discoverer.discover_hosts(args.target)
        print_discovery_results(results)
    except Exception as e:
        logging.error(f"Discovery failed: {e}")
        print(f"Error during discovery: {e}")


def handle_scan_command(args) -> None:
    """Handle the scan command."""
    try:
        print(f"Starting port scan on {args.target}...")
        scanner = PortScanner()
        results = scanner.scan_ports(args.target, args.ports)
        print_scan_results(results)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print(f"Error during scanning: {e}")


def handle_sniff_command(args) -> None:
    """Handle the sniff command."""
    try:
        print(f"Starting packet capture on interface {args.interface}...")
        sniffer = PacketSniffer()
        sniffer.start_sniffing(
            interface=args.interface,
            count=args.count,
            filter_expr=args.filter
        )
    except Exception as e:
        logging.error(f"Sniffing failed: {e}")
        print(f"Error during packet capture: {e}")


def handle_vuln_test_command(args) -> None:
    """Handle the vulnerability testing command."""
    try:
        print(f"Starting vulnerability testing on {args.target}...")
        tester = VulnerabilityTester()
        
        # Authorization required for vulnerability testing
        if not tester.authorize_target(args.target):
            print("Authorization failed. Testing aborted.")
            return
        
        if args.test_type == 'password':
            results = tester.password_strength_test(
                args.target, 
                args.port, 
                service=args.service,
                max_attempts=args.max_attempts
            )
            print(f"\nPassword Test Results:")
            print(f"Attempts: {results['attempts']}")
            print(f"Weak passwords found: {len(results['weak_passwords'])}")
            if results['weak_passwords']:
                print(f"Weak passwords: {', '.join(results['weak_passwords'])}")
        
        elif args.test_type == 'stress':
            results = tester.network_stress_test(
                args.target,
                args.port,
                duration=args.duration,
                connections_per_second=args.rate
            )
            print(f"\nStress Test Results:")
            print(f"Successful connections: {results['successful_connections']}")
            print(f"Failed connections: {results['failed_connections']}")
            if results.get('avg_response_time'):
                print(f"Average response time: {results['avg_response_time']:.3f}s")
        
        elif args.test_type == 'enumerate':
            ports = [int(p) for p in args.ports.split(',')]
            results = tester.service_enumeration(args.target, ports)
            print(f"\nService Enumeration Results:")
            print(f"Services found: {len(results['services'])}")
            print(f"Banners collected: {len(results['banners'])}")
            print(f"Potential vulnerabilities: {len(results['vulnerabilities'])}")
            
            for port, service in results['services'].items():
                print(f"Port {port}: {service['service']}")
                if service.get('version'):
                    print(f"  Version: {service['version']}")
    
    except Exception as e:
        logging.error(f"Vulnerability testing failed: {e}")
        print(f"Error during vulnerability testing: {e}")


def handle_advanced_test_command(args) -> None:
    """Handle the advanced testing command."""
    try:
        print(f"Starting advanced security testing...")
        tester = EthicalTester()
        
        # Start authorized session
        targets = [args.target] if isinstance(args.target, str) else args.target
        session_desc = f"Advanced {args.scan_type} security assessment"
        
        if not tester.start_authorized_session(targets, session_desc):
            print("Session not authorized. Testing aborted.")
            return
        
        # Perform advanced scan
        results = []
        for target in targets:
            print(f"\nTesting {target} with {args.scan_type} scan...")
            result = tester.advanced_vulnerability_scan(target, args.scan_type)
            results.append(result)
            
            if result.success:
                print(f"✅ Advanced scan completed successfully")
                # Show key findings
                data = result.data
                if data.get('confirmed_vulnerabilities'):
                    print(f"⚠️  {len(data['confirmed_vulnerabilities'])} vulnerabilities confirmed")
                if data.get('tcp_ports'):
                    open_ports = [str(p['port']) for p in data['tcp_ports'] if p['state'] == 'open']
                    print(f"🔍 Open ports: {', '.join(open_ports[:10])}")
            else:
                print(f"❌ Advanced scan failed: {result.message}")
        
        # Generate and display report
        if args.report:
            report = tester.generate_test_report(results)
            with open(args.report, 'w') as f:
                f.write(report)
            print(f"\n📄 Detailed report saved to {args.report}")
        
    except Exception as e:
        logging.error(f"Advanced testing failed: {e}")
        print(f"Error during advanced testing: {e}")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description='NetGuardian - A Modular Network Analysis Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py discover --target 192.168.1.0/24
  python main.py scan --target 192.168.1.1 --ports 1-1024
  python main.py sniff --interface en0 --count 100 --filter "tcp and port 80"
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discovery command
    discover_parser = subparsers.add_parser(
        'discover',
        help='Discover live hosts on a network'
    )
    discover_parser.add_argument(
        '--target',
        required=True,
        help='Target network range (e.g., 192.168.1.0/24)'
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Perform port scanning on a target'
    )
    scan_parser.add_argument(
        '--target',
        required=True,
        help='Target IP address'
    )
    scan_parser.add_argument(
        '--ports',
        default='1-1024',
        help='Port range to scan (default: 1-1024)'
    )
    
    # Sniff command
    sniff_parser = subparsers.add_parser(
        'sniff',
        help='Capture and analyze network packets'
    )
    sniff_parser.add_argument(
        '--interface',
        required=True,
        help='Network interface to capture on (e.g., en0)'
    )
    sniff_parser.add_argument(
        '--count',
        type=int,
        default=100,
        help='Number of packets to capture (default: 100)'
    )
    sniff_parser.add_argument(
        '--filter',
        default='',
        help='Packet filter expression (e.g., "tcp and port 80")'
    )
    
    # Vulnerability testing command
    vuln_parser = subparsers.add_parser(
        'vuln-test',
        help='Perform vulnerability testing (requires authorization)'
    )
    vuln_parser.add_argument(
        '--target',
        required=True,
        help='Target IP address'
    )
    vuln_parser.add_argument(
        '--test-type',
        required=True,
        choices=['password', 'stress', 'enumerate'],
        help='Type of vulnerability test to perform'
    )
    vuln_parser.add_argument(
        '--port',
        type=int,
        default=22,
        help='Target port (default: 22)'
    )
    vuln_parser.add_argument(
        '--service',
        default='ssh',
        help='Target service (ssh, ftp, telnet, http)'
    )
    vuln_parser.add_argument(
        '--max-attempts',
        type=int,
        default=10,
        help='Maximum password attempts (default: 10, max: 100)'
    )
    vuln_parser.add_argument(
        '--duration',
        type=int,
        default=10,
        help='Stress test duration in seconds (default: 10, max: 60)'
    )
    vuln_parser.add_argument(
        '--rate',
        type=int,
        default=10,
        help='Connections per second for stress test (default: 10, max: 50)'
    )
    vuln_parser.add_argument(
        '--ports',
        default='22,80,443',
        help='Comma-separated ports for enumeration (default: 22,80,443)'
    )
    
    # Advanced testing command
    advanced_parser = subparsers.add_parser(
        'advanced-test',
        help='Perform advanced security testing (requires explicit authorization)'
    )
    advanced_parser.add_argument(
        '--target',
        required=True,
        help='Target IP address or list of targets'
    )
    advanced_parser.add_argument(
        '--scan-type',
        default='comprehensive',
        choices=['stealth', 'comprehensive', 'aggressive'],
        help='Type of advanced scan (default: comprehensive)'
    )
    advanced_parser.add_argument(
        '--report',
        help='Save detailed report to file'
    )
    
    return parser


def main() -> None:
    """Main function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    
    # Check if a command was provided
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print("NetGuardian - Network Analysis Suite")
    print("="*40)
    
    # Route to appropriate command handler
    if args.command == 'discover':
        handle_discover_command(args)
    elif args.command == 'scan':
        handle_scan_command(args)
    elif args.command == 'sniff':
        handle_sniff_command(args)
    elif args.command == 'vuln-test':
        handle_vuln_test_command(args)
    elif args.command == 'advanced-test':
        handle_advanced_test_command(args)
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)
