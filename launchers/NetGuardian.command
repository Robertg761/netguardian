#!/bin/bash

# NetGuardian Network Analysis Suite Launcher
# This script opens Terminal and runs NetGuardian

# Set the path to the NetGuardian directory
NETGUARDIAN_PATH="/Users/robert/NetGuardian"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored text
print_color() {
    echo -e "${1}${2}${NC}"
}

# Clear screen and show banner
clear
print_color $BLUE "╔══════════════════════════════════════════════════════════════╗"
print_color $BLUE "║                    NetGuardian Launcher                      ║"
print_color $BLUE "║               Network Analysis Suite                         ║"
print_color $BLUE "╚══════════════════════════════════════════════════════════════╝"
echo
print_color $YELLOW "Starting NetGuardian Network Analysis Suite..."
echo

# Check if NetGuardian directory exists
if [ ! -d "$NETGUARDIAN_PATH" ]; then
    print_color $RED "Error: NetGuardian directory not found at $NETGUARDIAN_PATH"
    echo "Press any key to exit..."
    read -n 1
    exit 1
fi

# Change to NetGuardian directory
cd "$NETGUARDIAN_PATH"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    print_color $RED "Error: Python 3 is not installed or not in PATH"
    echo "Please install Python 3 and try again."
    echo "Press any key to exit..."
    read -n 1
    exit 1
fi

# Function to check dependencies
check_dependencies() {
    print_color $YELLOW "Checking dependencies..."
    
    # Check if requirements are installed
    if python3 -c "import scapy, nmap" 2>/dev/null; then
        print_color $GREEN "✓ Python dependencies are installed"
    else
        print_color $YELLOW "⚠ Some Python dependencies are missing"
        echo "Would you like to install them now? (y/n)"
        read -n 1 install_deps
        echo
        if [[ $install_deps =~ ^[Yy]$ ]]; then
            print_color $YELLOW "Installing Python dependencies..."
            pip3 install -r requirements.txt
        else
            print_color $RED "Dependencies are required to run NetGuardian"
            echo "Press any key to exit..."
            read -n 1
            exit 1
        fi
    fi
    
    # Check if nmap is installed
    if command -v nmap &> /dev/null; then
        print_color $GREEN "✓ nmap is installed"
    else
        print_color $YELLOW "⚠ nmap is not installed"
        echo "nmap is required for port scanning functionality"
        echo "Install with: brew install nmap"
        echo "Continue without nmap? (y/n)"
        read -n 1 continue_without_nmap
        echo
        if [[ ! $continue_without_nmap =~ ^[Yy]$ ]]; then
            echo "Press any key to exit..."
            read -n 1
            exit 1
        fi
    fi
}

# Function to show main menu
show_menu() {
    clear
    print_color $BLUE "╔══════════════════════════════════════════════════════════════╗"
    print_color $BLUE "║                    NetGuardian Main Menu                     ║"
    print_color $BLUE "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_color $GREEN "Select an option:"
    echo "1) Host Discovery (discover live hosts on network)"
    echo "2) Port Scanning (scan ports on a target)"
    echo "3) Packet Sniffing (capture network traffic)"
    echo "4) Vulnerability Testing (password/stress/enumeration)"
    echo "5) Advanced Security Testing (comprehensive assessment)"
    echo "6) Help & Examples"
    echo "7) Exit"
    echo
    print_color $YELLOW "Enter your choice (1-7): "
}

# Function to get network target
get_network_target() {
    echo
    print_color $YELLOW "Enter network range (e.g., 192.168.1.0/24): "
    read network_target
    if [ -z "$network_target" ]; then
        print_color $RED "Error: Network range cannot be empty"
        return 1
    fi
    echo "$network_target"
    return 0
}

# Function to get IP target
get_ip_target() {
    echo
    print_color $YELLOW "Enter target IP address (e.g., 192.168.1.1): "
    read ip_target
    if [ -z "$ip_target" ]; then
        print_color $RED "Error: IP address cannot be empty"
        return 1
    fi
    echo "$ip_target"
    return 0
}

# Function to get network interface
get_interface() {
    echo
    print_color $YELLOW "Available network interfaces:"
    python3 -c "
try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f'{i}) {iface}')
except:
    print('Could not list interfaces. Common interfaces: en0, en1, wi-fi')
"
    echo
    print_color $YELLOW "Enter interface name (e.g., en0): "
    read interface
    if [ -z "$interface" ]; then
        print_color $RED "Error: Interface cannot be empty"
        return 1
    fi
    echo "$interface"
    return 0
}

# Function to run host discovery
run_discovery() {
    print_color $BLUE "=== Host Discovery ==="
    target=$(get_network_target)
    if [ $? -eq 0 ]; then
        print_color $GREEN "Running: python3 main.py discover --target $target"
        echo
        python3 main.py discover --target "$target"
        echo
        print_color $YELLOW "Press any key to continue..."
        read -n 1
    fi
}

# Function to run port scanning
run_scan() {
    print_color $BLUE "=== Port Scanning ==="
    target=$(get_ip_target)
    if [ $? -eq 0 ]; then
        echo
        print_color $YELLOW "Enter port range (default: 1-1024, or specific ports like 22,80,443): "
        read ports
        if [ -z "$ports" ]; then
            ports="1-1024"
        fi
        
        print_color $GREEN "Running: python3 main.py scan --target $target --ports $ports"
        echo
        python3 main.py scan --target "$target" --ports "$ports"
        echo
        print_color $YELLOW "Press any key to continue..."
        read -n 1
    fi
}

# Function to run packet sniffing
run_sniff() {
    print_color $BLUE "=== Packet Sniffing ==="
    interface=$(get_interface)
    if [ $? -eq 0 ]; then
        echo
        print_color $YELLOW "Enter packet count (default: 50): "
        read count
        if [ -z "$count" ]; then
            count="50"
        fi
        
        print_color $YELLOW "Enter filter (optional, e.g., 'tcp and port 80'): "
        read filter
        
        cmd="python3 main.py sniff --interface $interface --count $count"
        if [ ! -z "$filter" ]; then
            cmd="$cmd --filter \"$filter\""
        fi
        
        print_color $GREEN "Running: $cmd"
        print_color $RED "Note: You may need to enter your password for packet capture"
        echo
        
        if [ ! -z "$filter" ]; then
            python3 main.py sniff --interface "$interface" --count "$count" --filter "$filter"
        else
            python3 main.py sniff --interface "$interface" --count "$count"
        fi
        
        echo
        print_color $YELLOW "Press any key to continue..."
        read -n 1
    fi
}

# Function to run vulnerability testing
run_vuln_test() {
    print_color $BLUE "=== Vulnerability Testing ==="
    print_color $RED "⚠️  WARNING: This requires authorization for target systems!"
    echo
    
    target=$(get_ip_target)
    if [ $? -eq 0 ]; then
        echo
        print_color $YELLOW "Select test type:"
        echo "1) Password Strength Testing"
        echo "2) Network Stress Testing"
        echo "3) Service Enumeration"
        echo
        print_color $YELLOW "Enter choice (1-3): "
        read test_choice
        
        case $test_choice in
            1)
                print_color $YELLOW "Enter port (default: 22): "
                read port
                if [ -z "$port" ]; then
                    port="22"
                fi
                
                print_color $YELLOW "Enter service (ssh/ftp/telnet, default: ssh): "
                read service
                if [ -z "$service" ]; then
                    service="ssh"
                fi
                
                print_color $GREEN "Running: python3 main.py vuln-test --target $target --test-type password --port $port --service $service"
                python3 main.py vuln-test --target "$target" --test-type password --port "$port" --service "$service"
                ;;
            2)
                print_color $YELLOW "Enter port (default: 80): "
                read port
                if [ -z "$port" ]; then
                    port="80"
                fi
                
                print_color $YELLOW "Enter duration in seconds (default: 10): "
                read duration
                if [ -z "$duration" ]; then
                    duration="10"
                fi
                
                print_color $GREEN "Running: python3 main.py vuln-test --target $target --test-type stress --port $port --duration $duration"
                python3 main.py vuln-test --target "$target" --test-type stress --port "$port" --duration "$duration"
                ;;
            3)
                print_color $YELLOW "Enter ports to enumerate (default: 22,80,443): "
                read ports
                if [ -z "$ports" ]; then
                    ports="22,80,443"
                fi
                
                print_color $GREEN "Running: python3 main.py vuln-test --target $target --test-type enumerate --ports $ports"
                python3 main.py vuln-test --target "$target" --test-type enumerate --ports "$ports"
                ;;
            *)
                print_color $RED "Invalid choice."
                ;;
        esac
        
        echo
        print_color $YELLOW "Press any key to continue..."
        read -n 1
    fi
}

# Function to run advanced testing
run_advanced_test() {
    print_color $BLUE "=== Advanced Security Testing ==="
    print_color $RED "🚨 CRITICAL WARNING: This requires EXPLICIT AUTHORIZATION!"
    print_color $RED "Only use on systems you OWN or have WRITTEN PERMISSION to test!"
    echo
    
    target=$(get_ip_target)
    if [ $? -eq 0 ]; then
        echo
        print_color $YELLOW "Select scan type:"
        echo "1) Stealth Scan (minimal footprint)"
        echo "2) Comprehensive Scan (recommended)"
        echo "3) Aggressive Scan (maximum testing)"
        echo
        print_color $YELLOW "Enter choice (1-3): "
        read scan_choice
        
        case $scan_choice in
            1) scan_type="stealth" ;;
            2) scan_type="comprehensive" ;;
            3) scan_type="aggressive" ;;
            *) 
                print_color $RED "Invalid choice."
                return
                ;;
        esac
        
        print_color $YELLOW "Save detailed report to file? (y/n): "
        read save_report
        
        cmd="python3 main.py advanced-test --target $target --scan-type $scan_type"
        if [[ $save_report =~ ^[Yy]$ ]]; then
            report_file="netguardian_report_$(date +%Y%m%d_%H%M%S).txt"
            cmd="$cmd --report $report_file"
        fi
        
        print_color $GREEN "Running: $cmd"
        print_color $RED "This will require multiple authorization confirmations!"
        echo
        
        eval $cmd
        
        echo
        print_color $YELLOW "Press any key to continue..."
        read -n 1
    fi
}

# Function to show help
show_help() {
    clear
    print_color $BLUE "╔══════════════════════════════════════════════════════════════╗"
    print_color $BLUE "║                    NetGuardian Help                         ║"
    print_color $BLUE "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_color $GREEN "Host Discovery Examples:"
    echo "  Target: 192.168.1.0/24    (scan local network)"
    echo "  Target: 10.0.0.0/28       (scan small subnet)"
    echo
    print_color $GREEN "Port Scanning Examples:"
    echo "  Target: 192.168.1.1       (single host)"
    echo "  Ports: 1-1024             (port range)"
    echo "  Ports: 22,80,443          (specific ports)"
    echo "  Ports: 1-100,443,8080     (mixed)"
    echo
    print_color $GREEN "Packet Sniffing Examples:"
    echo "  Interface: en0             (WiFi interface)"
    echo "  Interface: en1             (Ethernet interface)"
    echo "  Filter: tcp and port 80    (HTTP traffic only)"
    echo "  Filter: udp and port 53    (DNS traffic only)"
    echo
    print_color $YELLOW "⚠ Important Security Notes:"
    echo "• Only use on networks you own or have permission to test"
    echo "• Packet sniffing may require administrator privileges"
    echo "• Some features may be detected by network security systems"
    echo
    print_color $YELLOW "Press any key to return to main menu..."
    read -n 1
}

# Main execution
main() {
    check_dependencies
    
    while true; do
        show_menu
        read -n 1 choice
        echo
        
        case $choice in
            1)
                run_discovery
                ;;
            2)
                run_scan
                ;;
            3)
                run_sniff
                ;;
            4)
                run_vuln_test
                ;;
            5)
                run_advanced_test
                ;;
            6)
                show_help
                ;;
            7)
                print_color $GREEN "Thank you for using NetGuardian!"
                exit 0
                ;;
            *)
                print_color $RED "Invalid option. Please try again."
                sleep 1
                ;;
        esac
    done
}

# Check if running with sudo for packet capture
if [ "$EUID" -eq 0 ]; then
    print_color $YELLOW "Running with administrator privileges - packet capture will work without prompts"
fi

# Run main function
main
