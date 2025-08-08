#!/usr/bin/env python3
"""
NetGuardian Network Performance Monitoring Module
Provides network performance metrics collection and analysis.
"""

import logging
import time
import threading
import statistics
from typing import Dict, List, Any, Optional, Tuple
from collections import deque, defaultdict
from datetime import datetime, timedelta
import json
import subprocess
import socket
import struct
import select

try:
    from scapy.all import IP, ICMP, TCP, sr1, send, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Warning: Scapy not available. Some features will be limited.")

class NetworkPerformanceMonitor:
    """
    A class for monitoring network performance metrics including:
    - Latency (ping RTT)
    - Packet loss
    - Bandwidth estimation
    - Jitter
    - Network path analysis (traceroute)
    """
    
    def __init__(self, history_size: int = 1000):
        """
        Initialize the Network Performance Monitor.
        
        Args:
            history_size: Number of historical measurements to keep
        """
        self.logger = logging.getLogger(__name__)
        self.history_size = history_size
        
        # Performance data storage
        self.latency_history = defaultdict(lambda: deque(maxlen=history_size))
        self.packet_loss_history = defaultdict(lambda: deque(maxlen=history_size))
        self.bandwidth_history = defaultdict(lambda: deque(maxlen=history_size))
        self.jitter_history = defaultdict(lambda: deque(maxlen=history_size))
        
        # Monitoring threads
        self.monitoring_threads = {}
        self.stop_monitoring = threading.Event()
        
    def measure_latency(self, target: str, count: int = 10, 
                       timeout: float = 2.0) -> Dict[str, Any]:
        """
        Measure network latency to a target host.
        
        Args:
            target: Target IP or hostname
            count: Number of ping packets to send
            timeout: Timeout for each ping in seconds
            
        Returns:
            Dictionary containing latency statistics
        """
        results = {
            'target': target,
            'timestamp': time.time(),
            'packets_sent': count,
            'packets_received': 0,
            'packet_loss_percent': 0.0,
            'rtt_min': None,
            'rtt_max': None,
            'rtt_avg': None,
            'rtt_stddev': None,
            'all_rtts': []
        }
        
        rtts = []
        
        if HAS_SCAPY:
            # Use Scapy for more control
            for i in range(count):
                try:
                    start_time = time.time()
                    packet = IP(dst=target)/ICMP(id=i)
                    reply = sr1(packet, timeout=timeout, verbose=False)
                    
                    if reply:
                        rtt = (time.time() - start_time) * 1000  # Convert to ms
                        rtts.append(rtt)
                        results['packets_received'] += 1
                    
                except Exception as e:
                    self.logger.debug(f"Ping failed: {e}")
        else:
            # Fallback to system ping
            try:
                # Different ping commands for different OS
                import platform
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), target]
                else:
                    cmd = ['ping', '-c', str(count), '-W', str(int(timeout)), target]
                
                output = subprocess.check_output(cmd, text=True, timeout=count * timeout + 5)
                
                # Parse ping output (this is platform-specific)
                import re
                if platform.system().lower() == 'windows':
                    rtt_pattern = r'time=(\d+)ms'
                else:
                    rtt_pattern = r'time=(\d+\.?\d*) ms'
                
                matches = re.findall(rtt_pattern, output)
                rtts = [float(m) for m in matches]
                results['packets_received'] = len(rtts)
                
            except Exception as e:
                self.logger.error(f"System ping failed: {e}")
        
        # Calculate statistics
        if rtts:
            results['all_rtts'] = rtts
            results['rtt_min'] = min(rtts)
            results['rtt_max'] = max(rtts)
            results['rtt_avg'] = statistics.mean(rtts)
            if len(rtts) > 1:
                results['rtt_stddev'] = statistics.stdev(rtts)
            else:
                results['rtt_stddev'] = 0.0
        
        # Calculate packet loss
        if results['packets_sent'] > 0:
            results['packet_loss_percent'] = (
                (results['packets_sent'] - results['packets_received']) / 
                results['packets_sent'] * 100
            )
        
        # Store in history
        self.latency_history[target].append({
            'timestamp': results['timestamp'],
            'rtt_avg': results['rtt_avg'],
            'packet_loss': results['packet_loss_percent']
        })
        
        return results
    
    def measure_bandwidth(self, target: str, port: int = 80,
                         duration: float = 5.0) -> Dict[str, Any]:
        """
        Estimate bandwidth to a target host.
        
        Args:
            target: Target IP or hostname
            port: Target port
            duration: Test duration in seconds
            
        Returns:
            Dictionary containing bandwidth measurements
        """
        results = {
            'target': f"{target}:{port}",
            'timestamp': time.time(),
            'duration': duration,
            'bytes_sent': 0,
            'bytes_received': 0,
            'send_bandwidth_mbps': 0.0,
            'receive_bandwidth_mbps': 0.0,
            'test_type': 'tcp_throughput'
        }
        
        try:
            # Create TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            sock.connect((target, port))
            
            # Send data for bandwidth measurement
            test_data = b'X' * 1024  # 1KB chunks
            bytes_sent = 0
            bytes_received = 0
            
            sock.setblocking(False)
            end_time = start_time + duration
            
            while time.time() < end_time:
                # Try to send data
                try:
                    sent = sock.send(test_data)
                    bytes_sent += sent
                except socket.error:
                    pass
                
                # Try to receive data
                try:
                    data = sock.recv(4096)
                    if data:
                        bytes_received += len(data)
                except socket.error:
                    pass
                
                time.sleep(0.001)  # Small delay to prevent CPU spinning
            
            actual_duration = time.time() - start_time
            sock.close()
            
            # Calculate bandwidth
            results['bytes_sent'] = bytes_sent
            results['bytes_received'] = bytes_received
            results['send_bandwidth_mbps'] = (bytes_sent * 8 / actual_duration) / 1_000_000
            results['receive_bandwidth_mbps'] = (bytes_received * 8 / actual_duration) / 1_000_000
            
        except Exception as e:
            self.logger.error(f"Bandwidth measurement failed: {e}")
            results['error'] = str(e)
        
        # Store in history
        self.bandwidth_history[target].append({
            'timestamp': results['timestamp'],
            'send_mbps': results['send_bandwidth_mbps'],
            'receive_mbps': results['receive_bandwidth_mbps']
        })
        
        return results
    
    def measure_jitter(self, target: str, count: int = 20,
                      interval: float = 0.1) -> Dict[str, Any]:
        """
        Measure network jitter (variation in latency).
        
        Args:
            target: Target IP or hostname
            count: Number of measurements
            interval: Interval between measurements
            
        Returns:
            Dictionary containing jitter statistics
        """
        results = {
            'target': target,
            'timestamp': time.time(),
            'measurement_count': count,
            'jitter_ms': None,
            'jitter_min': None,
            'jitter_max': None,
            'jitter_avg': None,
            'latency_variations': []
        }
        
        # Collect latency measurements
        latencies = []
        for i in range(count):
            latency_result = self.measure_latency(target, count=1, timeout=2.0)
            if latency_result['rtt_avg'] is not None:
                latencies.append(latency_result['rtt_avg'])
            time.sleep(interval)
        
        # Calculate jitter (difference between consecutive latencies)
        if len(latencies) > 1:
            variations = []
            for i in range(1, len(latencies)):
                variation = abs(latencies[i] - latencies[i-1])
                variations.append(variation)
            
            results['latency_variations'] = variations
            results['jitter_min'] = min(variations)
            results['jitter_max'] = max(variations)
            results['jitter_avg'] = statistics.mean(variations)
            results['jitter_ms'] = results['jitter_avg']  # Primary jitter value
            
            # Calculate jitter standard deviation
            if len(variations) > 1:
                results['jitter_stddev'] = statistics.stdev(variations)
        
        # Store in history
        if results['jitter_ms'] is not None:
            self.jitter_history[target].append({
                'timestamp': results['timestamp'],
                'jitter': results['jitter_ms']
            })
        
        return results
    
    def traceroute(self, target: str, max_hops: int = 30,
                  timeout: float = 2.0) -> Dict[str, Any]:
        """
        Perform traceroute to discover network path.
        
        Args:
            target: Target IP or hostname
            max_hops: Maximum number of hops
            timeout: Timeout for each hop
            
        Returns:
            Dictionary containing traceroute results
        """
        results = {
            'target': target,
            'timestamp': time.time(),
            'max_hops': max_hops,
            'completed': False,
            'hops': []
        }
        
        try:
            # Resolve target IP
            target_ip = socket.gethostbyname(target)
            results['target_ip'] = target_ip
            
            if HAS_SCAPY:
                # Use Scapy for traceroute
                for ttl in range(1, max_hops + 1):
                    hop_info = {
                        'hop': ttl,
                        'ip': None,
                        'hostname': None,
                        'rtt': None,
                        'timeout': False
                    }
                    
                    try:
                        # Send packet with specific TTL
                        packet = IP(dst=target_ip, ttl=ttl)/ICMP()
                        start_time = time.time()
                        reply = sr1(packet, timeout=timeout, verbose=False)
                        
                        if reply:
                            rtt = (time.time() - start_time) * 1000
                            hop_info['ip'] = reply.src
                            hop_info['rtt'] = rtt
                            
                            # Try to resolve hostname
                            try:
                                hostname = socket.gethostbyaddr(reply.src)[0]
                                hop_info['hostname'] = hostname
                            except:
                                hop_info['hostname'] = reply.src
                            
                            # Check if we reached the target
                            if reply.src == target_ip:
                                results['completed'] = True
                                results['hops'].append(hop_info)
                                break
                        else:
                            hop_info['timeout'] = True
                    
                    except Exception as e:
                        hop_info['error'] = str(e)
                        hop_info['timeout'] = True
                    
                    results['hops'].append(hop_info)
            
            else:
                # Fallback to system traceroute
                import platform
                if platform.system().lower() == 'windows':
                    cmd = ['tracert', '-h', str(max_hops), '-w', str(int(timeout * 1000)), target]
                else:
                    cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), target]
                
                output = subprocess.check_output(cmd, text=True, timeout=max_hops * timeout + 10)
                
                # Parse traceroute output (simplified)
                lines = output.splitlines()
                hop_num = 0
                for line in lines:
                    if not line.strip():
                        continue
                    
                    # Look for hop information (this is platform-specific parsing)
                    import re
                    hop_pattern = r'^\s*(\d+)'
                    match = re.match(hop_pattern, line)
                    if match:
                        hop_num += 1
                        hop_info = {
                            'hop': hop_num,
                            'raw': line.strip()
                        }
                        
                        # Try to extract IP and RTT
                        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
                        rtt_pattern = r'(\d+\.?\d*)\s*ms'
                        
                        ip_match = re.search(ip_pattern, line)
                        if ip_match:
                            hop_info['ip'] = ip_match.group(1)
                        
                        rtt_matches = re.findall(rtt_pattern, line)
                        if rtt_matches:
                            hop_info['rtt'] = float(rtt_matches[0])
                        
                        results['hops'].append(hop_info)
                
                if results['hops'] and results['hops'][-1].get('ip') == target_ip:
                    results['completed'] = True
        
        except Exception as e:
            self.logger.error(f"Traceroute failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def start_continuous_monitoring(self, target: str, interval: float = 60.0,
                                  metrics: List[str] = None) -> str:
        """
        Start continuous monitoring of a target.
        
        Args:
            target: Target IP or hostname
            interval: Measurement interval in seconds
            metrics: List of metrics to monitor ['latency', 'bandwidth', 'jitter']
            
        Returns:
            Monitor ID for tracking
        """
        if metrics is None:
            metrics = ['latency']
        
        monitor_id = f"{target}_{int(time.time())}"
        
        def monitor_worker():
            while not self.stop_monitoring.is_set():
                try:
                    if 'latency' in metrics:
                        self.measure_latency(target)
                    
                    if 'bandwidth' in metrics:
                        self.measure_bandwidth(target)
                    
                    if 'jitter' in metrics:
                        self.measure_jitter(target, count=10)
                    
                except Exception as e:
                    self.logger.error(f"Monitoring error for {target}: {e}")
                
                # Wait for next interval
                self.stop_monitoring.wait(interval)
        
        # Start monitoring thread
        thread = threading.Thread(target=monitor_worker, daemon=True)
        thread.start()
        self.monitoring_threads[monitor_id] = thread
        
        self.logger.info(f"Started continuous monitoring for {target} (ID: {monitor_id})")
        return monitor_id
    
    def stop_continuous_monitoring(self, monitor_id: str = None):
        """
        Stop continuous monitoring.
        
        Args:
            monitor_id: Specific monitor to stop (None stops all)
        """
        self.stop_monitoring.set()
        
        if monitor_id and monitor_id in self.monitoring_threads:
            self.monitoring_threads[monitor_id].join(timeout=5)
            del self.monitoring_threads[monitor_id]
        else:
            # Stop all monitors
            for thread in self.monitoring_threads.values():
                thread.join(timeout=5)
            self.monitoring_threads.clear()
        
        self.stop_monitoring.clear()
        self.logger.info(f"Stopped monitoring: {monitor_id or 'all'}")
    
    def get_performance_summary(self, target: str, 
                               time_window: float = 3600) -> Dict[str, Any]:
        """
        Get performance summary for a target.
        
        Args:
            target: Target IP or hostname
            time_window: Time window in seconds (default: 1 hour)
            
        Returns:
            Performance summary statistics
        """
        current_time = time.time()
        cutoff_time = current_time - time_window
        
        summary = {
            'target': target,
            'time_window_seconds': time_window,
            'timestamp': current_time,
            'latency': {},
            'bandwidth': {},
            'jitter': {},
            'packet_loss': {}
        }
        
        # Analyze latency history
        latency_data = [
            d for d in self.latency_history[target]
            if d['timestamp'] > cutoff_time
        ]
        
        if latency_data:
            rtts = [d['rtt_avg'] for d in latency_data if d['rtt_avg'] is not None]
            losses = [d['packet_loss'] for d in latency_data]
            
            if rtts:
                summary['latency'] = {
                    'min': min(rtts),
                    'max': max(rtts),
                    'avg': statistics.mean(rtts),
                    'stddev': statistics.stdev(rtts) if len(rtts) > 1 else 0,
                    'samples': len(rtts)
                }
            
            if losses:
                summary['packet_loss'] = {
                    'min': min(losses),
                    'max': max(losses),
                    'avg': statistics.mean(losses),
                    'total_packets_lost': sum(losses),
                    'samples': len(losses)
                }
        
        # Analyze bandwidth history
        bandwidth_data = [
            d for d in self.bandwidth_history[target]
            if d['timestamp'] > cutoff_time
        ]
        
        if bandwidth_data:
            send_rates = [d['send_mbps'] for d in bandwidth_data]
            receive_rates = [d['receive_mbps'] for d in bandwidth_data]
            
            summary['bandwidth'] = {
                'send_mbps': {
                    'min': min(send_rates),
                    'max': max(send_rates),
                    'avg': statistics.mean(send_rates)
                },
                'receive_mbps': {
                    'min': min(receive_rates),
                    'max': max(receive_rates),
                    'avg': statistics.mean(receive_rates)
                },
                'samples': len(bandwidth_data)
            }
        
        # Analyze jitter history
        jitter_data = [
            d for d in self.jitter_history[target]
            if d['timestamp'] > cutoff_time
        ]
        
        if jitter_data:
            jitters = [d['jitter'] for d in jitter_data]
            summary['jitter'] = {
                'min': min(jitters),
                'max': max(jitters),
                'avg': statistics.mean(jitters),
                'samples': len(jitters)
            }
        
        # Calculate overall health score
        summary['health_score'] = self._calculate_health_score(summary)
        summary['health_status'] = self._get_health_status(summary['health_score'])
        
        return summary
    
    def _calculate_health_score(self, summary: Dict[str, Any]) -> float:
        """Calculate network health score (0-100)."""
        score = 100.0
        
        # Deduct for high latency
        if summary['latency']:
            avg_latency = summary['latency']['avg']
            if avg_latency > 200:
                score -= 20
            elif avg_latency > 100:
                score -= 10
            elif avg_latency > 50:
                score -= 5
        
        # Deduct for packet loss
        if summary['packet_loss']:
            avg_loss = summary['packet_loss']['avg']
            if avg_loss > 5:
                score -= 30
            elif avg_loss > 2:
                score -= 15
            elif avg_loss > 0.5:
                score -= 5
        
        # Deduct for high jitter
        if summary['jitter']:
            avg_jitter = summary['jitter']['avg']
            if avg_jitter > 50:
                score -= 15
            elif avg_jitter > 20:
                score -= 10
            elif avg_jitter > 10:
                score -= 5
        
        return max(0, min(100, score))
    
    def _get_health_status(self, score: float) -> str:
        """Get health status based on score."""
        if score >= 90:
            return 'EXCELLENT'
        elif score >= 75:
            return 'GOOD'
        elif score >= 60:
            return 'FAIR'
        elif score >= 40:
            return 'POOR'
        else:
            return 'CRITICAL'
    
    def export_performance_data(self, target: str, filepath: str,
                               format: str = 'json') -> None:
        """
        Export performance data to file.
        
        Args:
            target: Target to export data for
            filepath: Output file path
            format: Export format ('json', 'csv')
        """
        if format == 'json':
            data = {
                'target': target,
                'export_time': time.time(),
                'latency_history': list(self.latency_history[target]),
                'bandwidth_history': list(self.bandwidth_history[target]),
                'jitter_history': list(self.jitter_history[target]),
                'summary': self.get_performance_summary(target)
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif format == 'csv':
            import csv
            
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write latency data
                writer.writerow(['Latency History'])
                writer.writerow(['Timestamp', 'RTT (ms)', 'Packet Loss (%)'])
                for entry in self.latency_history[target]:
                    writer.writerow([
                        datetime.fromtimestamp(entry['timestamp']).isoformat(),
                        entry.get('rtt_avg', ''),
                        entry.get('packet_loss', '')
                    ])
                
                writer.writerow([])  # Empty row
                
                # Write bandwidth data
                writer.writerow(['Bandwidth History'])
                writer.writerow(['Timestamp', 'Send (Mbps)', 'Receive (Mbps)'])
                for entry in self.bandwidth_history[target]:
                    writer.writerow([
                        datetime.fromtimestamp(entry['timestamp']).isoformat(),
                        entry.get('send_mbps', ''),
                        entry.get('receive_mbps', '')
                    ])
        
        self.logger.info(f"Performance data exported to {filepath}")
