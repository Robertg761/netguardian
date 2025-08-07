# NetGuardian - Network Analysis Suite

🛡️ **A Comprehensive Network Security Analysis Toolkit**

**NetGuardian** is a modern, modular network analysis and security testing suite designed for ethical security professionals, network administrators, and cybersecurity enthusiasts. Built with Python, it offers both command-line and graphical interfaces for comprehensive network reconnaissance and security assessment.

## 🚀 Features

### Core Capabilities
- 🔍 **Host Discovery** - Identify active devices on networks
- 🔎 **Port Scanning** - Advanced service detection and enumeration
- 📡 **Packet Capture** - Real-time network traffic analysis
- 🔐 **Vulnerability Testing** - Password strength and service assessment
- 🎯 **Advanced Security Testing** - Comprehensive penetration testing tools
- 📊 **Professional Reporting** - Detailed analysis and export capabilities

### User Interfaces
- 💻 **Command Line Interface** - Full-featured CLI with all capabilities
- 🖥️ **Modern GUI** - User-friendly PyQt6-based graphical interface
- 📱 **Interactive Menu** - Guided terminal-based operation
- 🚀 **macOS App Bundles** - Native macOS application launchers

## 🛡️ Ethical Use Warning

**⚠️ IMPORTANT**: NetGuardian is designed for:
- ✅ Educational purposes and cybersecurity learning
- ✅ Authorized penetration testing with explicit permission
- ✅ Network analysis on systems you own
- ✅ Security research in controlled environments

**❌ DO NOT USE FOR**:
- Unauthorized network access or testing
- Malicious activities or illegal purposes
- Testing systems without explicit written permission

## 📦 Installation

### Prerequisites
- **Python 3.9+** (macOS includes Python 3.11)
- **Administrator privileges** (for packet capture)
- **nmap** (automatically prompted for installation)

### Quick Setup
```bash
git clone https://github.com/Robertg761/netguardian.git
cd netguardian
pip3 install -r requirements.txt
```

### macOS Installation
```bash
# Install nmap if needed
brew install nmap

# Run NetGuardian
python3 main.py --help
```

## 🚀 Usage

### Command Line Examples

**Network Discovery**
```bash
# Discover hosts on local network
python3 main.py discover --target 192.168.1.0/24

# Scan specific subnet
python3 main.py discover --target 10.0.0.0/28
```

**Port Scanning**
```bash
# Basic port scan
python3 main.py scan --target 192.168.1.100 --ports 1-1024

# Scan specific services
python3 main.py scan --target 192.168.1.100 --ports 22,80,443,8080
```

**Packet Capture**
```bash
# Monitor network traffic
sudo python3 main.py sniff --interface en0 --count 100

# Filter specific traffic
sudo python3 main.py sniff --interface en0 --filter "tcp and port 80"
```

### GUI Interface
For users who prefer graphical interfaces:

**Launch Options**:
- Double-click `launchers/NetGuardian-GUI.command`
- Or run: `cd gui && python3 netguardian_gui.py`

### Interactive Menu
For guided operation:
```bash
# Launch interactive menu
./launchers/NetGuardian.command
```

## 📁 Project Structure

```
netguardian/
├── main.py                 # Main CLI application
├── discovery.py            # Host discovery module
├── scanner.py             # Port scanning module
├── sniffer.py             # Packet capture module
├── vuln_testing.py        # Vulnerability testing
├── advanced_testing.py    # Advanced security tools
├── requirements.txt       # Python dependencies
├── gui/
│   └── netguardian_gui.py # PyQt6 GUI application
├── launchers/
│   ├── NetGuardian.command           # Terminal menu
│   └── NetGuardian-GUI.command       # GUI launcher
└── README.md
```

## 🔧 Advanced Features

### Vulnerability Testing
```bash
# Password strength testing
python3 main.py vuln-test --target 192.168.1.100 --test-type password --service ssh

# Service enumeration
python3 main.py vuln-test --target 192.168.1.100 --test-type enumerate --ports 22,80,443

# Network stress testing
python3 main.py vuln-test --target 192.168.1.100 --test-type stress --port 80 --duration 10
```

### Advanced Security Testing
```bash
# Comprehensive security assessment
python3 main.py advanced-test --target 192.168.1.100 --scan-type comprehensive

# Stealth reconnaissance
python3 main.py advanced-test --target 192.168.1.100 --scan-type stealth

# Aggressive testing (authorized use only)
python3 main.py advanced-test --target 192.168.1.100 --scan-type aggressive
```

## 📊 Output and Reporting

NetGuardian provides detailed output in multiple formats:
- **Console Output** - Real-time results with colored formatting
- **File Reports** - Save results to text files for analysis
- **Structured Data** - JSON output for integration with other tools

## 🛠️ Dependencies

- **scapy** - Packet manipulation and capture
- **python-nmap** - Nmap integration for advanced scanning
- **PyQt6** - Modern GUI framework (for graphical interface)
- **nmap** - Network mapping tool (external dependency)

## 💡 Use Cases

### Network Administration
- **Asset Discovery** - Identify all devices on corporate networks
- **Service Inventory** - Catalog running services and versions
- **Network Monitoring** - Track traffic patterns and anomalies

### Security Assessment
- **Penetration Testing** - Authorized security evaluations
- **Vulnerability Scanning** - Identify potential security weaknesses
- **Compliance Auditing** - Verify security policy implementation

### Education and Training
- **Cybersecurity Learning** - Hands-on network security education
- **Lab Environments** - Safe testing in controlled settings
- **Research Projects** - Network security research and development

## 🚨 Legal and Ethical Guidelines

### Authorization Requirements
1. **Written Permission** - Always obtain explicit authorization
2. **Scope Definition** - Clearly define testing boundaries
3. **Legal Compliance** - Follow all applicable laws and regulations
4. **Responsible Disclosure** - Report vulnerabilities ethically

### Built-in Safety Features
- **Authorization Prompts** - Multiple confirmation steps
- **Rate Limiting** - Prevent network overload
- **Audit Logging** - Track all testing activities
- **Safe Defaults** - Conservative settings by default

## 🤝 Contributing

We welcome contributions from the security community:

1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** your changes with tests
4. **Submit** a pull request

### Development Guidelines
- Follow Python PEP 8 style guidelines
- Include comprehensive documentation
- Maintain ethical use standards
- Add appropriate error handling

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

NetGuardian is provided for educational and authorized testing purposes only. Users are responsible for ensuring legal compliance. The developers assume no liability for misuse.

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Features**: Request features via GitHub Discussions
- **Security**: Contact maintainers privately for vulnerabilities

---

**Built with ❤️ for the cybersecurity community**

*Remember: Use your powers for good, always obtain permission, and help make the internet safer for everyone.*
