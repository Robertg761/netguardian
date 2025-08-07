# NetGuardian - A Modular Network Analysis Suite

NetGuardian is a comprehensive and modular network analysis tool designed for educational purposes and authorized security analysis on privately owned networks. Built with Python and designed specifically for macOS, this suite provides powerful capabilities for network discovery, port scanning, and packet analysis.

## ⚠️ Legal Notice

**IMPORTANT:** This tool is intended for educational purposes and authorized testing only. Use this tool only on networks that you own or have explicit written permission to test. Unauthorized network scanning or analysis may be illegal in your jurisdiction. The authors assume no responsibility for misuse of this software.

## 🎯 Core Philosophy

- **Modularity**: Built with distinct, self-contained modules for easy development and testing
- **Extensibility**: Clean, well-documented code that's easy to extend with new features
- **Ethical Design**: Designed specifically for legitimate network analysis and education

## 🚀 Features

### Phase 1: Host Discovery
- **ARP Scanning**: Efficient local network host discovery using ARP requests
- **Network Validation**: Automatic validation of CIDR notation and IP ranges
- **Stealth Mode**: Less detectable than traditional ping scans

### Phase 2: Port & Service Scanning  
- **TCP SYN Scanning**: Fast and stealthy port scanning
- **Service Detection**: Automatic service version identification
- **OS Fingerprinting**: Operating system detection capabilities
- **Flexible Port Ranges**: Support for single ports, ranges, and lists

### Phase 3: Packet Analysis
- **Real-time Capture**: Live packet capture and analysis
- **Protocol Analysis**: Support for TCP, UDP, ICMP, ARP, and DNS
- **Traffic Statistics**: Detailed capture statistics and protocol breakdown
- **Packet Filtering**: Berkeley Packet Filter (BPF) support

### Phase 4: Vulnerability Testing
- **Password Strength Testing**: Controlled brute force simulation
- **Network Stress Testing**: Controlled load testing and DDoS simulation
- **Service Enumeration**: Advanced banner grabbing and version detection
- **Default Credential Testing**: Common credential testing
- **Authorization Controls**: Multi-step authorization process

### Phase 5: Advanced Security Testing
- **Comprehensive Vulnerability Scanning**: Multi-technique vulnerability discovery
- **Protocol Fuzzing**: TCP flag manipulation and packet size testing
- **Evasion Testing**: Fragmentation, decoy, and timing evasion techniques
- **OS Fingerprinting**: Advanced operating system detection
- **Security Report Generation**: Detailed reporting with recommendations

## 📋 Requirements

### System Requirements
- **Operating System**: macOS (tested on macOS 10.15+)
- **Python**: Python 3.9 or higher
- **nmap**: Network exploration tool (`brew install nmap`)

### Python Dependencies
- `scapy>=2.4.5`: Packet manipulation and capture
- `python-nmap>=0.7.1`: Python interface to nmap

## 🛠️ Installation

1. **Clone or download NetGuardian**:
   ```bash
   git clone <repository-url>
   cd NetGuardian
   ```

2. **Install nmap** (required for port scanning):
   ```bash
   brew install nmap
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation**:
   ```bash
   python main.py --help
   ```

## 📖 Usage

### Command Structure
```bash
python main.py <command> [options]
```

### Host Discovery
Discover live hosts on a network using ARP scanning:

```bash
# Scan local network
python main.py discover --target 192.168.1.0/24

# Scan smaller subnet
python main.py discover --target 10.0.0.0/28
```

**Example Output:**
```
NetGuardian - Network Analysis Suite
========================================
Starting host discovery on 192.168.1.0/24...

==================================================
DISCOVERED HOSTS
==================================================
IP Address      MAC Address       
-----------------------------------
192.168.1.1     aa:bb:cc:dd:ee:ff 
192.168.1.10    11:22:33:44:55:66 
192.168.1.15    77:88:99:aa:bb:cc 

Total hosts discovered: 3
```

### Port Scanning
Perform comprehensive port scans on discovered hosts:

```bash
# Basic port scan (default: ports 1-1024)
python main.py scan --target 192.168.1.1

# Custom port range
python main.py scan --target 192.168.1.1 --ports 1-65535

# Specific ports
python main.py scan --target 192.168.1.1 --ports 22,80,443,8080

# Port range with specific ports
python main.py scan --target 192.168.1.1 --ports 1-100,443,8080-8090
```

**Example Output:**
```
============================================================
SCAN RESULTS FOR 192.168.1.1
============================================================
Host Status: up
Operating System: Linux 3.2 - 4.9 (96% accuracy)

Open Ports (4 found):
Port     Protocol   Service         Version
-------------------------------------------------------
22       tcp        ssh             OpenSSH 7.4 (protocol 2.0)
80       tcp        http            nginx 1.14.2
443      tcp        https           nginx 1.14.2
8080     tcp        http-proxy      N/A
```

### Packet Sniffing
Capture and analyze network traffic in real-time:

```bash
# Basic packet capture
python main.py sniff --interface en0 --count 50

# Capture with filter
python main.py sniff --interface en0 --count 100 --filter "tcp and port 80"

# Capture HTTPS traffic
python main.py sniff --interface en0 --count 200 --filter "tcp and port 443"

# Capture DNS queries
python main.py sniff --interface en0 --count 50 --filter "udp and port 53"

### Vulnerability Testing
Perform controlled security testing with proper authorization:

```bash
# Password strength testing (requires authorization)
python main.py vuln-test --target 192.168.1.1 --test-type password --service ssh --port 22

# Network stress testing (controlled load testing)
python main.py vuln-test --target 192.168.1.1 --test-type stress --port 80 --duration 30 --rate 20

# Service enumeration and banner grabbing
python main.py vuln-test --target 192.168.1.1 --test-type enumerate --ports 22,80,443,3389
```

### Advanced Security Testing
Comprehensive security assessment with multiple authorization layers:

```bash
# Stealth scan (minimal footprint)
python main.py advanced-test --target 192.168.1.1 --scan-type stealth --report stealth_report.txt

# Comprehensive scan (recommended)
python main.py advanced-test --target 192.168.1.1 --scan-type comprehensive --report full_assessment.txt

# Aggressive scan (maximum testing - use with extreme caution)
python main.py advanced-test --target 192.168.1.1 --scan-type aggressive --report aggressive_scan.txt
```
```

**Example Output:**
```
Starting packet capture on interface: en0
Capture count: 50
Filter: tcp and port 80
Press Ctrl+C to stop capture

Time         Protocol Source             Destination        Info
--------------------------------------------------------------------------------
14:32:01     TCP      192.168.1.100      93.184.216.34      Ports: 52341→80 Flags: SYN [HTTP]
14:32:01     TCP      93.184.216.34      192.168.1.100      Ports: 80→52341 Flags: SYN,ACK [HTTP]
14:32:01     TCP      192.168.1.100      93.184.216.34      Ports: 52341→80 Flags: ACK [HTTP]
```

### Advanced Options

**Verbose Logging**:
```bash
python main.py -v discover --target 192.168.1.0/24
```

**Getting Help**:
```bash
python main.py --help
python main.py discover --help
python main.py scan --help
python main.py sniff --help
```

## 🗂️ Project Structure

```
NetGuardian/
├── main.py           # Main entry point and CLI interface
├── discovery.py      # Host discovery module (ARP scanning)
├── scanner.py        # Port scanning module (nmap integration)
├── sniffer.py        # Packet capture and analysis module
├── vuln_testing.py   # Vulnerability testing module (authorized testing)
├── advanced_testing.py # Advanced security testing module (comprehensive)
├── requirements.txt  # Python dependencies
└── README.md        # This file
```

## 🔧 Module Details

### Discovery Module (`discovery.py`)
- **Purpose**: Discover live hosts on local networks
- **Method**: ARP scanning for efficiency and stealth
- **Features**: 
  - CIDR notation validation
  - Network information extraction
  - Single host checking
  - Comprehensive error handling

### Scanner Module (`scanner.py`)
- **Purpose**: Port scanning and service detection
- **Method**: Integration with nmap via python-nmap
- **Features**:
  - TCP SYN scanning (stealthy and fast)
  - Service version detection
  - OS fingerprinting
  - Flexible port specification
  - Quick scan presets

### Sniffer Module (`sniffer.py`)
- **Purpose**: Real-time packet capture and analysis
- **Method**: Scapy-based packet processing
- **Features**:
  - Multi-protocol support (TCP, UDP, ICMP, ARP, DNS)
  - Real-time traffic analysis
  - BPF filtering support
  - Traffic statistics
  - Packet-to-file capture

### Vulnerability Testing Module (`vuln_testing.py`)
- **Purpose**: Controlled security testing with authorization
- **Method**: Multi-layered testing with safety limits
- **Features**:
  - Password strength testing (brute force simulation)
  - Network stress testing (controlled load generation)
  - Service enumeration with banner grabbing
  - Authorization requirement system
  - Rate limiting and safety controls

### Advanced Testing Module (`advanced_testing.py`)
- **Purpose**: Comprehensive security assessment
- **Method**: Multi-technique vulnerability discovery
- **Features**:
  - Advanced vulnerability scanning
  - Protocol fuzzing and evasion testing
  - OS fingerprinting and service analysis
  - Comprehensive reporting
  - Multi-step authorization process

## 🛡️ Security Considerations

### Permissions
- **Root Access**: Some features may require root privileges on macOS
- **Network Interface Access**: Packet capture requires appropriate permissions
- **Firewall**: Ensure your firewall settings allow the necessary network operations

### Best Practices
1. **Always** get written permission before scanning networks you don't own
2. **Test** on isolated lab networks when possible
3. **Document** your testing activities
4. **Respect** rate limits to avoid overwhelming target systems
5. **Follow** your organization's security policies
6. **Use vulnerability testing responsibly** - only on authorized systems
7. **Stop testing immediately** if you discover unauthorized activity
8. **Follow responsible disclosure** for any vulnerabilities found

## 🚨 Troubleshooting

### Common Issues

**"Interface not found" error**:
```bash
# List available interfaces
python sniffer.py --list-interfaces

# Use the correct interface name
python main.py sniff --interface en1 --count 10
```

**"nmap not found" error**:
```bash
# Install nmap using Homebrew
brew install nmap

# Verify installation
nmap --version
```

**Permission denied errors**:
```bash
# Run with sudo for packet capture (if needed)
sudo python main.py sniff --interface en0 --count 10
```

**No hosts discovered**:
- Verify you're on the correct network
- Check that the target range is correct
- Ensure ARP traffic isn't being blocked
- Try a smaller subnet range

**"Authorization failed" errors**:
- Advanced testing requires explicit authorization
- Follow the multi-step authorization process
- Ensure you have written permission for target systems
- Only test on systems you own or have explicit permission to test

### Getting More Information

Enable verbose logging for detailed information:
```bash
python main.py -v discover --target 192.168.1.0/24
```

## 🔮 Future Enhancements

### Current Advanced Features (v2.0)
- **Multi-Layer Authorization**: Comprehensive authorization system for advanced testing
- **Protocol Fuzzing**: TCP flag manipulation, packet size testing, header fuzzing
- **Evasion Testing**: Fragmentation, decoy scanning, timing evasion techniques
- **Advanced Vulnerability Scanning**: Multi-technique security assessment
- **Comprehensive Reporting**: Detailed security reports with recommendations
- **Ethical Safeguards**: Built-in safety limits and ethical guidelines

### Planned Features (v3.0)
- **Web Interface**: Browser-based GUI for easier operation
- **Database Integration**: Store and track scan results over time
- **Export Capabilities**: Export results in various formats (PDF, CSV, JSON)
- **Advanced Filtering**: More sophisticated packet filtering options
- **Network Mapping**: Visual representation of discovered networks
- **Automated Scanning**: Scheduled and recurring scans
- **Machine Learning**: AI-powered vulnerability detection

### Contributing
This project is designed to be easily extensible. Each module is self-contained and follows consistent patterns, making it straightforward to add new features or modify existing functionality.

## 📄 License

This software is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## 📞 Support

For issues, questions, or contributions:
1. Review this README thoroughly
2. Check the troubleshooting section
3. Examine the module documentation and comments
4. Test individual modules using their standalone functionality

---

**Remember**: With great power comes great responsibility. Use NetGuardian ethically and legally.
