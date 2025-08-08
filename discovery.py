#!/usr/bin/env python3
"""
NetGuardian Discovery Module
Provides host and service discovery functionality:
- ARP host discovery on local IPv4 networks (scapy)
- mDNS/Bonjour service discovery (zeroconf)
- UPnP/SSDP discovery
- IPv6 neighbors (system ndp)
- Bluetooth Low Energy device scan (bleak)
- Nearby Wi‑Fi SSIDs (airport)

Note: Some features require platform support and permissions. BLE scanning on
macOS requires Bluetooth permissions in the app's Info.plist.
"""

import logging
import ipaddress
from typing import List, Dict, Optional, Callable, Any
import re
import socket
import subprocess
import platform
import asyncio
import os
from shutil import which

# macOS airport utility path for Wi‑Fi info
_AIRPORT_BIN = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'

# Optional vendor lookup for MAC addresses
try:
    from manuf import manuf as _manuf
    _manuf_parser = _manuf.MacParser()
except Exception:
    _manuf_parser = None

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr
    # Disable scapy's verbose output
    conf.verb = 0
except ImportError:
    raise ImportError(
        "scapy is required for host discovery. Install with: pip install scapy"
    )

# Optional: psutil for interface netmask lookup (used in get_local_networks)
try:
    import psutil as _psutil
except Exception:
    _psutil = None

def _get_netmask_for_iface(iface: str) -> Optional[str]:
    """Best-effort netmask lookup for an interface using psutil if available."""
    try:
        if _psutil is None:
            return None
        addrs = _psutil.net_if_addrs().get(iface, [])
        for info in addrs:
            if getattr(info, 'family', None) == socket.AF_INET:
                return getattr(info, 'netmask', None)
    except Exception:
        return None
    return None


class HostDiscoverer:
    """
    A class for discovering live hosts and services on local networks.

    Includes ARP host discovery and optional extended discovery (mDNS/Bonjour,
    SSDP/UPnP, IPv6 neighbors, BLE devices, and Wi‑Fi SSIDs).
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
        """
        return self.discover_hosts_enhanced(target_range)

    def discover_hosts_enhanced(
        self,
        target_range: str,
        resolve_hostnames: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        batch_size: int = 128
    ) -> List[Dict[str, str]]:
        """
        Discover live hosts with optional hostname resolution and progress.
        
        Args:
            target_range: Network CIDR to scan
            resolve_hostnames: If True, attempt reverse DNS for each host
            progress_callback: Optional callback(current, total) for UI updates
            batch_size: Number of IPs per ARP batch
        """
        # Validate input
        if not self.validate_network_range(target_range):
            raise ValueError(f"Invalid network range: {target_range}")
        
        self.logger.info(f"Starting ARP scan on {target_range}")
        
        try:
            # Build list of target IPs
            network = ipaddress.ip_network(target_range, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]
            total = len(all_ips)
            if total == 0:
                return []
            
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            discovered: Dict[str, Dict[str, str]] = {}
            
            for i in range(0, total, batch_size):
                batch_ips = all_ips[i:i+batch_size]
                arp_request = ARP(pdst=batch_ips)
                pkt = broadcast / arp_request
                self.logger.debug(f"Sending ARP batch {i}-{i+len(batch_ips)-1} with timeout {self.timeout}s")
                answered_list = srp(pkt, timeout=self.timeout, verbose=False)[0]
                
                for _, received in answered_list:
                    ip = received.psrc
                    mac = received.hwsrc
                    vendor = ''
                    try:
                        if _manuf_parser is not None and mac:
                            vendor = _manuf_parser.get_manuf_long(mac) or (_manuf_parser.get_manuf(mac) or '')
                    except Exception:
                        vendor = ''
                    discovered[ip] = {'ip': ip, 'mac': mac, 'vendor': vendor}
                    self.logger.debug(f"Discovered host: {ip} ({mac})")
                
                if progress_callback:
                    progress_callback(min(i+len(batch_ips), total), total)
            
            results = list(discovered.values())
            
            # Optional hostname resolution
            if resolve_hostnames and results:
                for host in results:
                    try:
                        host['hostname'] = socket.gethostbyaddr(host['ip'])[0]
                    except Exception:
                        host['hostname'] = ''
            
            self.logger.info(f"Discovery completed. Found {len(results)} hosts")
            return results
        except Exception as e:
            msg = str(e)
            # Fallback path: unprivileged discovery if ARP requires root (macOS BPF /dev/bpf0)
            if 'Permission denied' in msg or 'cannot open BPF' in msg or '/dev/bpf' in msg:
                self.logger.warning("ARP requires elevated privileges; falling back to unprivileged ping sweep")
                return self._discover_hosts_unprivileged(target_range, resolve_hostnames, progress_callback)
            error_msg = f"ARP scan failed: {msg}"
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

    def get_local_networks_detailed(self) -> List[Dict[str, str]]:
        """
        Enumerate local networks with interface detail.
        Returns list of dicts: {'cidr','iface','ip','netmask'}
        """
        details: List[Dict[str, str]] = []

        def _add_detail(ip_str: str, mask_str: str, iface: Optional[str] = None):
            try:
                net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                cidr = str(net)
                if not any(d.get('cidr') == cidr for d in details):
                    details.append({'cidr': cidr, 'iface': iface or '', 'ip': ip_str, 'netmask': str(net.netmask)})
            except Exception:
                pass

        # Method 1: scapy route table (no interface names)
        try:
            for route in conf.route.routes:
                if len(route) < 4:
                    continue
                net, mask = route[0], route[1]
                try:
                    net_ip = ipaddress.IPv4Address(net)
                    mask_ip = ipaddress.IPv4Address(mask)
                except Exception:
                    continue
                if int(net_ip) == 0 or int(mask_ip) == 0:
                    continue
                try:
                    network = ipaddress.IPv4Network((int(net_ip), int(mask_ip)), strict=False)
                    cidr = str(network)
                    if not any(d.get('cidr') == cidr for d in details):
                        details.append({'cidr': cidr, 'iface': '', 'ip': str(network.network_address), 'netmask': str(network.netmask)})
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"Error reading local networks from routes: {e}")

        # Method 2: scapy + psutil for iface/netmask
        try:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    mask = _get_netmask_for_iface(iface)
                    if not ip or ip == '0.0.0.0' or not mask or mask == '0.0.0.0':
                        continue
                    _add_detail(ip, mask, iface)
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"Error deriving networks from interfaces: {e}")

        # Method 3: ifconfig parsing (macOS)
        if platform.system() == 'Darwin':
            try:
                ifconfig_path = '/sbin/ifconfig' if os.path.exists('/sbin/ifconfig') else 'ifconfig'
                out = subprocess.check_output([ifconfig_path, '-a'], text=True, timeout=5)
                cur_iface = None
                for line in out.splitlines():
                    if not line.startswith('\t') and ':' in line:
                        cur_iface = line.split(':', 1)[0]
                    line = line.strip()
                    if line.startswith('inet '):
                        parts = line.split()
                        try:
                            ip = parts[1]
                            mask_str = ''
                            if 'netmask' in parts:
                                nm_idx = parts.index('netmask')
                                nm_val = parts[nm_idx + 1]
                                if nm_val.startswith('0x'):
                                    nm_int = int(nm_val, 16)
                                    mask_str = socket.inet_ntoa(nm_int.to_bytes(4, 'big'))
                                else:
                                    mask_str = nm_val
                            if ip and mask_str:
                                _add_detail(ip, mask_str, cur_iface)
                        except Exception:
                            continue
            except Exception as e:
                self.logger.debug(f"ifconfig parsing failed: {e}")

        # Method 4: networksetup/ipconfig (macOS)
        if platform.system() == 'Darwin':
            try:
                networksetup_path = '/usr/sbin/networksetup' if os.path.exists('/usr/sbin/networksetup') else 'networksetup'
                ipconfig_path = '/usr/sbin/ipconfig' if os.path.exists('/usr/sbin/ipconfig') else 'ipconfig'
                hwports = subprocess.check_output([networksetup_path, '-listallhardwareports'], text=True, timeout=5)
                device = None
                cur_name = None
                for line in hwports.splitlines():
                    if line.startswith('Hardware Port:'):
                        cur_name = line.split(':', 1)[1].strip()
                    if line.startswith('Device:'):
                        dev = line.split(':', 1)[1].strip()
                        if cur_name in ('Wi-Fi', 'Ethernet'):
                            device = dev
                            break
                if device:
                    try:
                        ip = subprocess.check_output([ipconfig_path, 'getifaddr', device], text=True, timeout=3).strip()
                        nm = subprocess.check_output([ipconfig_path, 'getifnetmask', device], text=True, timeout=3).strip()
                        if ip and nm:
                            _add_detail(ip, nm, device)
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"networksetup/ipconfig failed: {e}")

        # Method 5: psutil fallback
        if _psutil is not None:
            try:
                addrs = _psutil.net_if_addrs()
                for iface, infos in addrs.items():
                    for i in infos:
                        if getattr(i, 'family', None) == socket.AF_INET:
                            ip = i.address
                            mask = i.netmask
                            if ip and mask and ip != '127.0.0.1':
                                _add_detail(ip, mask, iface)
            except Exception as e:
                self.logger.debug(f"psutil fallback failed: {e}")

        # Try to enrich with SSID label for Wi‑Fi interfaces on macOS
        if platform.system() == 'Darwin':
            for d in details:
                if d.get('iface', '').startswith('en'):
                    ssid = self._current_ssid_for_iface(d.get('iface', ''))
                    if ssid:
                        d['ssid'] = ssid
        return details

    def _current_ssid_for_iface(self, iface: str) -> Optional[str]:
        """Return the current SSID for a Wi‑Fi interface on macOS, if connected."""
        try:
            if platform.system() != 'Darwin' or not os.path.exists(_AIRPORT_BIN):
                return None
            # airport -I prints a status block; look for SSID: line
            out = subprocess.check_output([_AIRPORT_BIN, '-I'], text=True, timeout=3)
            ssid = None
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith('ssid:'):
                    ssid = line.split(':', 1)[1].strip()
                elif line.lower().startswith('agrctlrssi:'):
                    # presence of block indicates valid; continue
                    pass
            return ssid
        except Exception:
            return None

    def get_local_networks(self) -> List[str]:
        """
        Enumerate local networks (CIDRs).
        Returns list of CIDR strings.
        """
        try:
            return [d['cidr'] for d in self.get_local_networks_detailed()]
        except Exception:
            return []

    # ------------ Extended discovery features -------------
    def discover_mdns_services(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """
        Discover mDNS/Bonjour services using zeroconf.
        Returns a list of service records with name, type, addresses, and port.
        """
        try:
            from zeroconf import Zeroconf, ServiceBrowser
        except Exception as e:
            self.logger.debug(f"zeroconf not available: {e}")
            return []

        records: List[Dict[str, Any]] = []

        class Listener:
            def add_service(self, zc, stype, name):
                try:
                    info = zc.get_service_info(stype, name, 3000)
                    if not info:
                        return
                    addrs = []
                    for addr in info.addresses:
                        try:
                            addrs.append(socket.inet_ntoa(addr))
                        except Exception:
                            try:
                                addrs.append(socket.inet_ntop(socket.AF_INET6, addr))
                            except Exception:
                                pass
                    records.append({
                        'type': 'mDNS',
                        'name': info.name or name,
                        'service_type': stype,
                        'port': info.port,
                        'addresses': addrs,
                        'properties': {k.decode(): v.decode(errors='ignore') if isinstance(v, bytes) else str(v)
                                       for k, v in (info.properties or {}).items()}
                    })
                except Exception as e:
                    self.logger.debug(f"mDNS parse error: {e}")

        zc = Zeroconf()
        listener = Listener()
        # Common service types; wildcard browsing is not directly supported, so browse a set
        common_types = [
            '_services._dns-sd._udp.local.',
            '_http._tcp.local.', '_https._tcp.local.', '_ssh._tcp.local.',
            '_smb._tcp.local.', '_afpovertcp._tcp.local.', '_ipp._tcp.local.',
            '_printer._tcp.local.', '_airplay._tcp.local.', '_raop._tcp.local.'
        ]
        browsers = [ServiceBrowser(zc, st, listener) for st in common_types]
        try:
            import time
            t0 = time.time()
            while time.time() - t0 < timeout:
                time.sleep(0.1)
        finally:
            zc.close()
        return records

    def discover_ssdp(self, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """Discover UPnP/SSDP devices via M-SEARCH multicast."""
        results: List[Dict[str, Any]] = []
        MSEARCH = ("M-SEARCH * HTTP/1.1\r\n"
                   "HOST: 239.255.255.250:1900\r\n"
                   "MAN: \"ssdp:discover\"\r\n"
                   "MX: 2\r\n"
                   "ST: ssdp:all\r\n\r\n").encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(timeout)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.sendto(MSEARCH, ("239.255.255.250", 1900))
            while True:
                try:
                    data, addr = s.recvfrom(65507)
                    text = data.decode(errors='ignore')
                    headers = {}
                    for line in text.split('\r\n'):
                        if ':' in line:
                            k, v = line.split(':', 1)
                            headers[k.strip().upper()] = v.strip()
                    results.append({
                        'type': 'SSDP',
                        'from': addr[0],
                        'st': headers.get('ST', ''),
                        'usn': headers.get('USN', ''),
                        'location': headers.get('LOCATION', '')
                    })
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.debug(f"SSDP discovery error: {e}")
        finally:
            try:
                s.close()
            except Exception:
                pass
        return results

    def list_ipv6_neighbors(self) -> List[Dict[str, str]]:
        """List IPv6 neighbors using system 'ndp -an' on macOS."""
        if platform.system() != 'Darwin':
            return []
        try:
            ndp_path = '/usr/sbin/ndp' if os.path.exists('/usr/sbin/ndp') else 'ndp'
            out = subprocess.check_output([ndp_path, '-an'], text=True, timeout=5)
            neighbors: List[Dict[str, str]] = []
            for line in out.splitlines():
                # Format: fe80::1%en0 ...  xx:xx:xx:xx:xx:xx ...
                parts = line.split()
                if len(parts) >= 5 and parts[0].startswith(('fe80::', '2001:', 'fd', 'fc')):
                    ip = parts[0]
                    mac = parts[1] if ':' in parts[1] else parts[4]
                    neighbors.append({'type': 'IPv6', 'ip': ip, 'mac': mac})
            return neighbors
        except Exception as e:
            self.logger.debug(f"IPv6 neighbors error: {e}")
            return []

    async def _ble_scan_async(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        try:
            from bleak import BleakScanner
        except Exception as e:
            self.logger.debug(f"bleak not available: {e}")
            return []
        devices = await BleakScanner.discover(timeout=timeout)
        results: List[Dict[str, Any]] = []
        for d in devices:
            results.append({
                'type': 'BLE',
                'address': getattr(d, 'address', ''),
                'name': getattr(d, 'name', '') or '',
                'rssi': getattr(d, 'rssi', None)
            })
        return results

    def scan_ble_devices(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Scan for BLE devices using bleak (requires Bluetooth permission)."""
        try:
            return asyncio.run(self._ble_scan_async(timeout=timeout))
        except Exception as e:
            self.logger.debug(f"BLE scan error: {e}")
            return []

    def list_wifi_networks(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """List nearby Wi‑Fi SSIDs via macOS 'airport -s'."""
        airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        if not os.path.exists(airport):
            return []
        try:
            out = subprocess.check_output([airport, '-s'], text=True, timeout=timeout)
            lines = out.splitlines()
            if not lines:
                return []
            results: List[Dict[str, Any]] = []
            # Header like: SSID BSSID RSSI CHANNEL HT CC SECURITY (variable spacing)
            for line in lines[1:]:
                if not line.strip():
                    continue
                # Split by multiple spaces
                cols = re.split(r"\s{2,}", line.strip())
                if len(cols) >= 3:
                    ssid = cols[0]
                    bssid = cols[1] if len(cols) > 1 else ''
                    rssi = cols[2] if len(cols) > 2 else ''
                    security = cols[-1] if cols else ''
                    results.append({'type': 'WiFi', 'ssid': ssid, 'bssid': bssid, 'rssi': rssi, 'security': security})
            return results
        except Exception as e:
            self.logger.debug(f"Wi‑Fi list error: {e}")
            return []

    def discover_extended(
        self,
        target_range: str,
        resolve_hostnames: bool = False,
        include_mdns: bool = True,
        include_ssdp: bool = True,
        include_ipv6: bool = True,
        include_ble: bool = False,
        include_wifi: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Run ARP discovery and optional extended discovery, returning a dict."""
        hosts = self.discover_hosts_enhanced(target_range, resolve_hostnames, progress_callback)
        extras: List[Dict[str, Any]] = []
        if include_mdns:
            extras.extend(self.discover_mdns_services())
        if include_ssdp:
            extras.extend(self.discover_ssdp())
        if include_ipv6:
            extras.extend(self.list_ipv6_neighbors())
        if include_ble:
            extras.extend(self.scan_ble_devices())
        if include_wifi:
            extras.extend(self.list_wifi_networks())
        return {'hosts': hosts, 'extras': extras}


    def _discover_hosts_unprivileged(
        self,
        target_range: str,
        resolve_hostnames: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict[str, str]]:
        """Unprivileged host discovery using ping sweep and ARP cache parsing.
        This avoids raw packet capture and works without sudo on macOS.
        """
        try:
            network = ipaddress.ip_network(target_range, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            total = len(hosts)
            if total == 0:
                return []
            # Ping in small batches concurrently
            import concurrent.futures
            def ping(ip: str) -> Optional[str]:
                try:
                    # macOS ping uses -c count, -W timeout (in ms)
                    subprocess.run(['ping', '-c', '1', '-W', '500', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return ip
                except Exception:
                    return None
            responded: List[str] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                futures = {ex.submit(ping, ip): ip for ip in hosts}
                done = 0
                for fut in concurrent.futures.as_completed(futures):
                    val = fut.result()
                    if val:
                        responded.append(val)
                    done += 1
                    if progress_callback and done % 16 == 0:
                        progress_callback(done, total)
            # Parse ARP cache to get MACs
            mac_map: Dict[str, str] = {}
            try:
                out = subprocess.check_output(['arp', '-an'], text=True, timeout=5)
                for line in out.splitlines():
                    # (? at ) at 1a:2b:... on en0 ifscope [ethernet]
                    m = re.search(r'\((?P<ip>[^)]+)\) at (?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.IGNORECASE)
                    if m:
                        mac_map[m.group('ip')] = m.group('mac').lower()
            except Exception:
                pass
            results: List[Dict[str, str]] = []
            for ip in responded:
                entry: Dict[str, str] = {'ip': ip, 'mac': mac_map.get(ip, '')}
                # Optional reverse DNS
                if resolve_hostnames:
                    try:
                        entry['hostname'] = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        entry['hostname'] = ''
                # Vendor
                if entry.get('mac') and _manuf_parser is not None:
                    try:
                        entry['vendor'] = _manuf_parser.get_manuf_long(entry['mac']) or (_manuf_parser.get_manuf(entry['mac']) or '')
                    except Exception:
                        pass
                results.append(entry)
            return results
        except Exception as e:
            raise RuntimeError(f"Unprivileged discovery failed: {e}")

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
