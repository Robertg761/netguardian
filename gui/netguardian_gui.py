#!/usr/bin/env python3
"""
NetGuardian GUI - Modern Desktop Interface
A comprehensive GUI for the NetGuardian network analysis suite.
"""

import sys
import os
import threading
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QGridLayout,
    QWidget, QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit,
    QSpinBox, QComboBox, QCheckBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QGroupBox, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMenuBar, QStatusBar, QToolBar, QFrame, QScrollArea, QFormLayout,
    QMessageBox, QFileDialog, QDialog, QDialogButtonBox, QSlider,
    QButtonGroup, QRadioButton
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QObject, QSize, QRect
)
from PyQt6.QtGui import (
    QFont, QPixmap, QIcon, QAction, QPalette, QColor, QLinearGradient,
    QPainter, QBrush, QPen
)

# Add NetGuardian project paths so bundled app can import local modules
# Add the project root to the path to allow for direct imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    # Import project modules normally
    from discovery import HostDiscoverer
    from scanner import PortScanner
    from sniffer import PacketSniffer
    from vuln_testing import VulnerabilityTester
    from advanced_testing import EthicalTester
except ImportError as e:
    print(f"Warning: Could not import NetGuardian modules: {e}")
    print("GUI will run in demo mode.")
    # Define dummy classes for demo mode
    class HostDiscoverer: pass
    class PortScanner: pass
    class PacketSniffer: pass
    class VulnerabilityTester: pass
    class EthicalTester: pass


class ModernStyle:
    """Modern dark theme styling constants."""
    
    # Color palette
    DARK_BG = "#1e1e2e"
    LIGHT_BG = "#313244"
    ACCENT_BLUE = "#89b4fa"
    ACCENT_GREEN = "#a6e3a1"
    ACCENT_ORANGE = "#fab387"
    ACCENT_RED = "#f38ba8"
    TEXT_PRIMARY = "#cdd6f4"
    TEXT_SECONDARY = "#a6adc8"
    BORDER = "#45475a"
    
    @staticmethod
    def get_stylesheet():
        return f"""
        QMainWindow {{
            background-color: {ModernStyle.DARK_BG};
            color: {ModernStyle.TEXT_PRIMARY};
        }}
        
        QTabWidget::pane {{
            border: 1px solid {ModernStyle.BORDER};
            background-color: {ModernStyle.LIGHT_BG};
        }}
        
        QTabWidget::tab-bar {{
            left: 5px;
        }}
        
        QTabBar::tab {{
            background-color: {ModernStyle.DARK_BG};
            color: {ModernStyle.TEXT_SECONDARY};
            border: 1px solid {ModernStyle.BORDER};
            padding: 8px 16px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
            font-weight: bold;
        }}
        
        QTabBar::tab:hover:!selected {{
            background-color: {ModernStyle.LIGHT_BG};
            color: {ModernStyle.TEXT_PRIMARY};
        }}
        
        QPushButton {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
            border: none;
            padding: 10px 20px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 6px;
        }}
        
        QPushButton:hover {{
            background-color: #7aa2f7;
        }}
        
        QPushButton:pressed {{
            background-color: #6c7cd4;
        }}
        
        QPushButton:disabled {{
            background-color: {ModernStyle.BORDER};
            color: {ModernStyle.TEXT_SECONDARY};
        }}
        
        QPushButton.danger {{
            background-color: {ModernStyle.ACCENT_RED};
        }}
        
        QPushButton.success {{
            background-color: {ModernStyle.ACCENT_GREEN};
        }}
        
        QPushButton.warning {{
            background-color: {ModernStyle.ACCENT_ORANGE};
        }}
        
        QLineEdit, QTextEdit, QSpinBox, QComboBox {{
            background-color: {ModernStyle.LIGHT_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            border: 2px solid {ModernStyle.BORDER};
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
        }}
        
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
            border-color: {ModernStyle.ACCENT_BLUE};
        }}
        
        QGroupBox {{
            font-weight: bold;
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 8px;
            margin-top: 1ex;
            color: {ModernStyle.TEXT_PRIMARY};
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
        }}
        
        QTableWidget {{
            background-color: {ModernStyle.LIGHT_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            border: 1px solid {ModernStyle.BORDER};
            gridline-color: {ModernStyle.BORDER};
        }}
        
        QTableWidget::item {{
            padding: 8px;
        }}
        
        QTableWidget::item:selected {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
        }}
        
        QHeaderView::section {{
            background-color: {ModernStyle.DARK_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            padding: 8px;
            border: 1px solid {ModernStyle.BORDER};
            font-weight: bold;
        }}
        
        QProgressBar {{
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 5px;
            text-align: center;
            background-color: {ModernStyle.LIGHT_BG};
        }}
        
        QProgressBar::chunk {{
            background-color: {ModernStyle.ACCENT_GREEN};
            border-radius: 3px;
        }}
        
        QTreeWidget {{
            background-color: {ModernStyle.LIGHT_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            border: 1px solid {ModernStyle.BORDER};
        }}
        
        QTreeWidget::item:selected {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
        }}
        
        QStatusBar {{
            background-color: {ModernStyle.DARK_BG};
            color: {ModernStyle.TEXT_SECONDARY};
            border-top: 1px solid {ModernStyle.BORDER};
        }}
        
        QMenuBar {{
            background-color: {ModernStyle.DARK_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            border-bottom: 1px solid {ModernStyle.BORDER};
        }}
        
        QMenuBar::item:selected {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
        }}
        
        QMenu {{
            background-color: {ModernStyle.LIGHT_BG};
            color: {ModernStyle.TEXT_PRIMARY};
            border: 1px solid {ModernStyle.BORDER};
        }}
        
        QMenu::item:selected {{
            background-color: {ModernStyle.ACCENT_BLUE};
            color: {ModernStyle.DARK_BG};
        }}
        
        QCheckBox {{
            color: {ModernStyle.TEXT_PRIMARY};
            spacing: 8px;
        }}
        
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
        }}
        
        QCheckBox::indicator:unchecked {{
            border: 2px solid {ModernStyle.BORDER};
            background-color: {ModernStyle.LIGHT_BG};
            border-radius: 3px;
        }}
        
        QCheckBox::indicator:checked {{
            border: 2px solid {ModernStyle.ACCENT_GREEN};
            background-color: {ModernStyle.ACCENT_GREEN};
            border-radius: 3px;
        }}
        
        QRadioButton {{
            color: {ModernStyle.TEXT_PRIMARY};
            spacing: 8px;
        }}
        
        QRadioButton::indicator {{
            width: 18px;
            height: 18px;
        }}
        
        QRadioButton::indicator:unchecked {{
            border: 2px solid {ModernStyle.BORDER};
            background-color: {ModernStyle.LIGHT_BG};
            border-radius: 9px;
        }}
        
        QRadioButton::indicator:checked {{
            border: 2px solid {ModernStyle.ACCENT_BLUE};
            background-color: {ModernStyle.ACCENT_BLUE};
            border-radius: 9px;
        }}
        
        QSlider::groove:horizontal {{
            border: 1px solid {ModernStyle.BORDER};
            height: 8px;
            background: {ModernStyle.LIGHT_BG};
            margin: 2px 0;
            border-radius: 4px;
        }}
        
        QSlider::handle:horizontal {{
            background: {ModernStyle.ACCENT_BLUE};
            border: 1px solid {ModernStyle.BORDER};
            width: 18px;
            margin: -2px 0;
            border-radius: 9px;
        }}
        
        QSlider::handle:horizontal:hover {{
            background: #7aa2f7;
        }}
        """


class NetworkWorker(QThread):
    """Worker thread for network operations to prevent GUI freezing."""
    
    finished = pyqtSignal(str, object)  # operation_type, results
    progress = pyqtSignal(str)  # status message
    error = pyqtSignal(str)  # error message
    packet = pyqtSignal(dict)  # per-packet signal for sniffing
    discover_progress = pyqtSignal(int, int)  # current, total
    
    def __init__(self, operation_type: str, **kwargs):
        super().__init__()
        self.operation_type = operation_type
        self.kwargs = kwargs
        self.running = True
    
    def run(self):
        try:
            if self.operation_type == 'discover':
                self.discover_hosts()
            elif self.operation_type == 'scan':
                self.scan_ports()
            elif self.operation_type == 'sniff':
                self.sniff_packets()
            elif self.operation_type == 'vuln_test':
                self.vulnerability_test()
            elif self.operation_type == 'advanced_test':
                self.advanced_test()
        except Exception as e:
            self.error.emit(str(e))
    
    def discover_hosts(self):
        self.progress.emit("Initializing host discovery...")
        discoverer = HostDiscoverer()
        target = self.kwargs.get('target')
        resolve = self.kwargs.get('resolve', False)
        include_mdns = self.kwargs.get('include_mdns', True)
        include_ssdp = self.kwargs.get('include_ssdp', True)
        include_ipv6 = self.kwargs.get('include_ipv6', True)
        include_ble = self.kwargs.get('include_ble', False)
        include_wifi = self.kwargs.get('include_wifi', True)
        
        self.progress.emit(f"Scanning network: {target}")
        
        def cb(cur, total):
            self.discover_progress.emit(cur, total)
        
        results = discoverer.discover_extended(
            target,
            resolve_hostnames=resolve,
            include_mdns=include_mdns,
            include_ssdp=include_ssdp,
            include_ipv6=include_ipv6,
            include_ble=include_ble,
            include_wifi=include_wifi,
            progress_callback=cb,
        )
        
        host_count = len(results.get('hosts', []))
        extra_count = len(results.get('extras', []))
        self.progress.emit(f"Discovery complete. Found {host_count} hosts and {extra_count} services/devices.")
        self.finished.emit('discover', results)
    
    def scan_ports(self):
        self.progress.emit("Initializing port scanner...")
        scanner = PortScanner()
        target = self.kwargs.get('target')
        ports = self.kwargs.get('ports', '1-1024')
        
        self.progress.emit(f"Scanning ports on {target}...")
        results = scanner.scan_ports(target, ports)
        
        self.progress.emit("Port scan complete.")
        self.finished.emit('scan', results)
    
    def sniff_packets(self):
        self.progress.emit("Starting packet capture...")
        sniffer = PacketSniffer()
        interface = self.kwargs.get('interface')
        count = self.kwargs.get('count', 100)
        filter_expr = self.kwargs.get('filter', '')
        
        self.progress.emit(f"Capturing {count} packets on {interface}...")
        
        try:
            sniffer.start_sniffing(
                interface=interface,
                count=count,
                filter_expr=filter_expr,
                on_packet=lambda info: self.packet.emit(info),
                verbose_print=False
            )
            self.progress.emit("Packet capture complete.")
            self.finished.emit('sniff', {'message': 'Packet capture completed'})
        except Exception as e:
            self.error.emit(str(e))
    
    def vulnerability_test(self):
        self.progress.emit("Starting vulnerability test...")
        # Implementation would depend on specific test type
        self.progress.emit("Vulnerability test complete.")
        self.finished.emit('vuln_test', {'message': 'Test completed'})
    
    def advanced_test(self):
        self.progress.emit("Starting advanced security test...")
        # Implementation would use EthicalTester
        self.progress.emit("Advanced test complete.")
        self.finished.emit('advanced_test', {'message': 'Advanced test completed'})
    
    def stop(self):
        self.running = False


class HostDiscoveryTab(QWidget):
    """Tab for network host discovery functionality."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.worker = None
        self.local_networks_cached = []
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Configuration section
        config_group = QGroupBox("Discovery Configuration")
        config_layout = QFormLayout()
        
        # Target network input with helper
        target_row = QHBoxLayout()
        self.target_input = QLineEdit("192.168.1.0/24")
        self.target_input.setPlaceholderText("Enter target network (e.g., 192.168.1.0/24)")
        self.local_nets_combo = QComboBox()
        self.local_nets_combo.setMinimumWidth(220)
        self.local_nets_combo.setEditable(False)
        self.refresh_nets_btn = QPushButton("🔄 Local Networks")
        self.refresh_nets_btn.setToolTip("List local networks detected on this system")
        self.refresh_nets_btn.clicked.connect(self.load_local_networks)
        
        target_row.addWidget(self.target_input, 3)
        target_row.addWidget(self.local_nets_combo, 2)
        target_row.addWidget(self.refresh_nets_btn, 1)
        
        config_layout.addRow("Target Network:", target_row)
        
        # Options
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(5)
        self.timeout_spin.setSuffix(" seconds")
        config_layout.addRow("Timeout:", self.timeout_spin)
        
        self.resolve_names_chk = QCheckBox("Resolve hostnames")
        self.resolve_names_chk.setChecked(False)
        
        # Extended discovery toggles
        self.ext_mdns_chk = QCheckBox("mDNS/Bonjour")
        self.ext_mdns_chk.setChecked(True)
        self.ext_ssdp_chk = QCheckBox("UPnP/SSDP")
        self.ext_ssdp_chk.setChecked(True)
        self.ext_ipv6_chk = QCheckBox("IPv6 neighbors")
        self.ext_ipv6_chk.setChecked(True)
        self.ext_ble_chk = QCheckBox("Bluetooth LE (requires permission)")
        self.ext_ble_chk.setChecked(False)
        self.ext_wifi_chk = QCheckBox("Nearby Wi‑Fi SSIDs")
        self.ext_wifi_chk.setChecked(True)
        
        opts_layout = QVBoxLayout()
        opts_layout.addWidget(self.resolve_names_chk)
        opts_layout.addWidget(self.ext_mdns_chk)
        opts_layout.addWidget(self.ext_ssdp_chk)
        opts_layout.addWidget(self.ext_ipv6_chk)
        opts_layout.addWidget(self.ext_wifi_chk)
        opts_layout.addWidget(self.ext_ble_chk)
        opts_container = QWidget()
        opts_container.setLayout(opts_layout)
        config_layout.addRow("Options:", opts_container)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🔍 Start Discovery")
        self.start_button.clicked.connect(self.start_discovery)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setProperty("class", "danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_discovery)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("📄 Export Results")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress and status
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to discover hosts")
        layout.addWidget(self.status_label)
        
        # Results tables
        results_group = QGroupBox("Discovery Results")
        results_layout = QVBoxLayout()
        
        # Hosts table
        host_label = QLabel("Hosts (ARP)")
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "Hostname", "Status"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(host_label)
        results_layout.addWidget(self.results_table)

        # Extras table (mDNS/SSDP/IPv6/Wi‑Fi/BLE)
        extras_label = QLabel("Services & Nearby Devices (mDNS, SSDP, IPv6, Wi‑Fi, BLE)")
        self.extras_table = QTableWidget()
        self.extras_table.setColumnCount(5)
        self.extras_table.setHorizontalHeaderLabels(["Type", "Name/SSID", "Address", "Port/RSSI", "Details"])
        self.extras_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(extras_label)
        results_layout.addWidget(self.extras_table)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.setLayout(layout)
        
        # Preload local networks
        self.load_local_networks()
    
    def start_discovery(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target network.")
            return
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.export_button.setEnabled(False)
        
        # Start worker thread
        self.worker = NetworkWorker(
            'discover',
            target=target,
            resolve=self.resolve_names_chk.isChecked(),
            include_mdns=self.ext_mdns_chk.isChecked(),
            include_ssdp=self.ext_ssdp_chk.isChecked(),
            include_ipv6=self.ext_ipv6_chk.isChecked(),
            include_ble=self.ext_ble_chk.isChecked(),
            include_wifi=self.ext_wifi_chk.isChecked(),
        )
        self.worker.progress.connect(self.update_status)
        self.worker.discover_progress.connect(self.on_discover_progress)
        self.worker.finished.connect(self.discovery_finished)
        self.worker.error.connect(self.discovery_error)
        self.worker.start()
    
    def load_local_networks(self):
        try:
            discoverer = HostDiscoverer()
            nets_detailed = []
            try:
                nets_detailed = discoverer.get_local_networks_detailed()  # type: ignore[attr-defined]
            except Exception:
                # Fallback to legacy list
                nets = discoverer.get_local_networks()
                nets_detailed = [{'cidr': n, 'iface': '', 'ip': '', 'netmask': ''} for n in nets]
            self.local_networks_cached = nets_detailed
            self.local_nets_combo.clear()
            if nets_detailed:
                for item in nets_detailed:
                    display = f"{(item.get('iface') or 'iface?')} · {item.get('cidr')}" if item.get('iface') else item.get('cidr')
                    self.local_nets_combo.addItem(display, userData=item.get('cidr'))
                # When selecting, set target input to CIDR from userData
                def _on_change(_text):
                    data = self.local_nets_combo.currentData()
                    if data:
                        self.target_input.setText(str(data))
                self.local_nets_combo.currentTextChanged.connect(_on_change)
            else:
                self.local_nets_combo.addItem("No local networks found")
        except Exception as e:
            self.local_nets_combo.clear()
            self.local_nets_combo.addItem("Error listing networks")
            # Surface error in status for troubleshooting
            self.status_label.setText(f"Error listing networks: {str(e)}")
        
    def stop_discovery(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.terminate()
            self.worker.wait()
        
        self.reset_ui()
        self.status_label.setText("Discovery stopped by user")
    
    def discovery_finished(self, operation_type, results):
        self.reset_ui()
        
        if results:
            # results could be from extend discovery path
            if isinstance(results, dict):
                hosts = results.get('hosts', [])
                extras = results.get('extras', [])
                self.populate_results_table(hosts)
                self.populate_extras_table(extras)
                self.status_label.setText(f"Discovery complete. Found {len(hosts)} hosts and {len(extras)} services/devices.")
            else:
                self.populate_results_table(results)
                self.status_label.setText(f"Discovery complete. Found {len(results)} hosts.")
            self.export_button.setEnabled(True)
        else:
            self.status_label.setText("Discovery complete. No hosts found.")
    
    def discovery_error(self, error_msg):
        self.reset_ui()
        self.status_label.setText(f"Error: {error_msg}")
        QMessageBox.critical(self, "Discovery Error", error_msg)
    
    def update_status(self, message):
        self.status_label.setText(message)
    
    def on_discover_progress(self, current, total):
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)
    
    def populate_results_table(self, results):
        self.results_table.setRowCount(len(results))
        
        for row, host in enumerate(results):
            self.results_table.setItem(row, 0, QTableWidgetItem(host.get('ip', 'Unknown')))
            self.results_table.setItem(row, 1, QTableWidgetItem(host.get('mac', 'Unknown')))
            self.results_table.setItem(row, 2, QTableWidgetItem(host.get('vendor', '')))
            self.results_table.setItem(row, 3, QTableWidgetItem(host.get('hostname', '')))
            self.results_table.setItem(row, 4, QTableWidgetItem("Active"))

    def populate_extras_table(self, items):
        self.extras_table.setRowCount(len(items))
        for row, item in enumerate(items):
            typ = item.get('type', '')
            name = item.get('name', '') or item.get('ssid', '') or item.get('service_type', '')
            addr = ''
            port_or_rssi = ''
            details = ''
            if typ == 'mDNS':
                addr = ", ".join(item.get('addresses', []))
                port_or_rssi = str(item.get('port', ''))
                props = item.get('properties', {})
                details = ", ".join(f"{k}={v}" for k, v in props.items())
            elif typ == 'SSDP':
                addr = item.get('from', '')
                details = item.get('location', '')
                name = item.get('st', name)
            elif typ == 'IPv6':
                addr = item.get('ip', '')
                details = item.get('mac', '')
            elif typ == 'WiFi':
                name = item.get('ssid', '')
                addr = item.get('bssid', '')
                port_or_rssi = str(item.get('rssi', ''))
                details = item.get('security', '')
            elif typ == 'BLE':
                name = item.get('name', '') or item.get('address', '')
                addr = item.get('address', '')
                port_or_rssi = str(item.get('rssi', ''))
            self.extras_table.setItem(row, 0, QTableWidgetItem(typ))
            self.extras_table.setItem(row, 1, QTableWidgetItem(name))
            self.extras_table.setItem(row, 2, QTableWidgetItem(addr))
            self.extras_table.setItem(row, 3, QTableWidgetItem(port_or_rssi))
            self.extras_table.setItem(row, 4, QTableWidgetItem(details))
    
    def reset_ui(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
    
    def export_results(self):
        if self.results_table.rowCount() == 0 and getattr(self, 'extras_table', None) and self.extras_table.rowCount() == 0:
            QMessageBox.information(self, "Export", "No results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Discovery Results", 
            f"discovery_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Hosts
                    f.write("[Hosts]\nIP Address,MAC Address,Vendor,Hostname,Status\n")
                    for row in range(self.results_table.rowCount()):
                        ip = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else ''
                        mac = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else ''
                        vendor = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else ''
                        hostname = self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else ''
                        status = self.results_table.item(row, 4).text() if self.results_table.item(row, 4) else ''
                        f.write(f"{ip},{mac},{vendor},{hostname},{status}\n")
                    # Extras
                    if getattr(self, 'extras_table', None):
                        f.write("\n[Services & Nearby]\nType,Name/SSID,Address,Port/RSSI,Details\n")
                        for row in range(self.extras_table.rowCount()):
                            t = self.extras_table.item(row, 0).text() if self.extras_table.item(row, 0) else ''
                            n = self.extras_table.item(row, 1).text() if self.extras_table.item(row, 1) else ''
                            a = self.extras_table.item(row, 2).text() if self.extras_table.item(row, 2) else ''
                            p = self.extras_table.item(row, 3).text() if self.extras_table.item(row, 3) else ''
                            d = self.extras_table.item(row, 4).text() if self.extras_table.item(row, 4) else ''
                            f.write(f"{t},{n},{a},{p},{d}\n")
                
                QMessageBox.information(self, "Export", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))


class PortScanTab(QWidget):
    """Tab for port scanning functionality."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.worker = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Configuration section
        config_group = QGroupBox("Scan Configuration")
        config_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP address")
        config_layout.addRow("Target IP:", self.target_input)
        
        self.ports_input = QLineEdit("1-1024")
        self.ports_input.setPlaceholderText("e.g., 1-1024, 80,443, 22-25")
        config_layout.addRow("Port Range:", self.ports_input)
        
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP SYN Scan", "TCP Connect Scan", "UDP Scan", "Comprehensive"])
        config_layout.addRow("Scan Type:", self.scan_type)
        
        self.timing_slider = QSlider(Qt.Orientation.Horizontal)
        self.timing_slider.setRange(1, 5)
        self.timing_slider.setValue(3)
        self.timing_label = QLabel("Normal")
        timing_layout = QHBoxLayout()
        timing_layout.addWidget(self.timing_slider)
        timing_layout.addWidget(self.timing_label)
        config_layout.addRow("Scan Speed:", timing_layout)
        
        self.timing_slider.valueChanged.connect(self.update_timing_label)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QGridLayout()
        
        self.os_detection = QCheckBox("OS Detection")
        self.service_version = QCheckBox("Service Version Detection")
        self.service_version.setChecked(True)
        self.aggressive_scan = QCheckBox("Aggressive Scan")
        
        advanced_layout.addWidget(self.os_detection, 0, 0)
        advanced_layout.addWidget(self.service_version, 0, 1)
        advanced_layout.addWidget(self.aggressive_scan, 0, 2)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🔍 Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setProperty("class", "danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("📄 Export Results")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress and status
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan ports")
        layout.addWidget(self.status_label)
        
        # Results
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Port results table
        port_group = QGroupBox("Open Ports")
        port_layout = QVBoxLayout()
        
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(4)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Protocol", "Service", "Version"])
        
        port_layout.addWidget(self.ports_table)
        port_group.setLayout(port_layout)
        splitter.addWidget(port_group)
        
        # Host information
        info_group = QGroupBox("Host Information")
        info_layout = QVBoxLayout()
        
        self.host_info = QTextEdit()
        self.host_info.setReadOnly(True)
        self.host_info.setMaximumHeight(200)
        
        info_layout.addWidget(self.host_info)
        info_group.setLayout(info_layout)
        splitter.addWidget(info_group)
        
        layout.addWidget(splitter)
        
        self.setLayout(layout)
    
    def update_timing_label(self, value):
        timing_labels = {1: "Very Slow", 2: "Slow", 3: "Normal", 4: "Fast", 5: "Very Fast"}
        self.timing_label.setText(timing_labels[value])
    
    def start_scan(self):
        target = self.target_input.text().strip()
        ports = self.ports_input.text().strip()
        
        if not target or not ports:
            QMessageBox.warning(self, "Warning", "Please enter target IP and port range.")
            return
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.ports_table.setRowCount(0)
        self.host_info.clear()
        self.export_button.setEnabled(False)
        
        # Start worker thread
        self.worker = NetworkWorker('scan', target=target, ports=ports)
        self.worker.progress.connect(self.update_status)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.scan_error)
        self.worker.start()
    
    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.terminate()
            self.worker.wait()
        
        self.reset_ui()
        self.status_label.setText("Scan stopped by user")
    
    def scan_finished(self, operation_type, results):
        self.reset_ui()
        
        if results and results.get('ports'):
            self.populate_results(results)
            port_count = len(results['ports'])
            self.status_label.setText(f"Scan complete. Found {port_count} open ports.")
            self.export_button.setEnabled(True)
        else:
            self.status_label.setText("Scan complete. No open ports found.")
    
    def scan_error(self, error_msg):
        self.reset_ui()
        self.status_label.setText(f"Error: {error_msg}")
        QMessageBox.critical(self, "Scan Error", error_msg)
    
    def update_status(self, message):
        self.status_label.setText(message)
    
    def populate_results(self, results):
        # Populate ports table
        ports = results.get('ports', [])
        self.ports_table.setRowCount(len(ports))
        
        for row, port in enumerate(ports):
            self.ports_table.setItem(row, 0, QTableWidgetItem(str(port.get('port', ''))))
            self.ports_table.setItem(row, 1, QTableWidgetItem(port.get('protocol', '')))
            self.ports_table.setItem(row, 2, QTableWidgetItem(port.get('service', '')))
            self.ports_table.setItem(row, 3, QTableWidgetItem(port.get('version', '')))
        
        # Populate host info
        host_info_text = f"""Host: {results.get('host', 'Unknown')}
Status: {results.get('status', 'Unknown')}
OS: {results.get('os', 'Unknown')}

Scan Summary:
- Total open ports: {len(ports)}
- Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        self.host_info.setPlainText(host_info_text)
    
    def reset_ui(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
    
    def export_results(self):
        if self.ports_table.rowCount() == 0:
            QMessageBox.information(self, "Export", "No results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Results", 
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("Port,Protocol,Service,Version\n")
                    for row in range(self.ports_table.rowCount()):
                        port = self.ports_table.item(row, 0).text()
                        protocol = self.ports_table.item(row, 1).text()
                        service = self.ports_table.item(row, 2).text()
                        version = self.ports_table.item(row, 3).text()
                        f.write(f"{port},{protocol},{service},{version}\n")
                
                QMessageBox.information(self, "Export", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))


class PacketSnifferTab(QWidget):
    """Tab for packet sniffing functionality."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.worker = None
        self.captured_packets = []
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Configuration section
        config_group = QGroupBox("Capture Configuration")
        config_layout = QFormLayout()
        
        self.interface_combo = QComboBox()
        # Populate interfaces dynamically with fallback values
        try:
            from sniffer import PacketSniffer
            interfaces = PacketSniffer().get_available_interfaces()
        except Exception:
            interfaces = []
        if not interfaces:
            interfaces = ["en0", "en1", "eth0", "wlan0"]
        self.interface_combo.addItems(interfaces)
        config_layout.addRow("Interface:", self.interface_combo)
        
        self.packet_count = QSpinBox()
        self.packet_count.setRange(1, 10000)
        self.packet_count.setValue(100)
        config_layout.addRow("Packet Count:", self.packet_count)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp and port 80")
        config_layout.addRow("Filter:", self.filter_input)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Quick filters
        filter_group = QGroupBox("Quick Filters")
        filter_layout = QHBoxLayout()
        
        quick_filters = [
            ("All Traffic", ""),
            ("HTTP", "tcp and port 80"),
            ("HTTPS", "tcp and port 443"),
            ("DNS", "udp and port 53"),
            ("SSH", "tcp and port 22"),
            ("FTP", "tcp and port 21")
        ]
        
        for name, filter_expr in quick_filters:
            btn = QPushButton(name)
            btn.clicked.connect(lambda checked, f=filter_expr: self.filter_input.setText(f))
            filter_layout.addWidget(btn)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("📡 Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setProperty("class", "danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.clear_button = QPushButton("🗑️ Clear")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        self.save_button = QPushButton("💾 Save Capture")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_capture)
        button_layout.addWidget(self.save_button)
        
        layout.addLayout(button_layout)
        
        # Progress and status
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to capture packets")
        layout.addWidget(self.status_label)
        
        # Results
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Packet list
        packet_group = QGroupBox("Captured Packets")
        packet_layout = QVBoxLayout()
        
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.selectionModel().selectionChanged.connect(self.packet_selected)
        
        packet_layout.addWidget(self.packet_table)
        packet_group.setLayout(packet_layout)
        splitter.addWidget(packet_group)
        
        # Packet details
        details_group = QGroupBox("Packet Details")
        details_layout = QVBoxLayout()
        
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setMaximumHeight(200)
        
        details_layout.addWidget(self.packet_details)
        details_group.setLayout(details_layout)
        splitter.addWidget(details_group)
        
        layout.addWidget(splitter)
        
        # Statistics
        stats_group = QGroupBox("Capture Statistics")
        stats_layout = QGridLayout()
        
        self.stats_labels = {}
        stats_items = [
            ("Total Packets", "total"), ("TCP Packets", "tcp"),
            ("UDP Packets", "udp"), ("ICMP Packets", "icmp"),
            ("ARP Packets", "arp"), ("Other", "other")
        ]
        
        for i, (label, key) in enumerate(stats_items):
            label_widget = QLabel(f"{label}:")
            value_widget = QLabel("0")
            value_widget.setAlignment(Qt.AlignmentFlag.AlignRight)
            
            stats_layout.addWidget(label_widget, i // 3, (i % 3) * 2)
            stats_layout.addWidget(value_widget, i // 3, (i % 3) * 2 + 1)
            
            self.stats_labels[key] = value_widget
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        self.setLayout(layout)
    
    def start_capture(self):
        interface = self.interface_combo.currentText()
        count = self.packet_count.value()
        filter_expr = self.filter_input.text().strip()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.captured_packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        
        # Start worker thread
        self.worker = NetworkWorker('sniff', interface=interface, count=count, filter=filter_expr)
        self.worker.progress.connect(self.update_status)
        self.worker.finished.connect(self.capture_finished)
        self.worker.error.connect(self.capture_error)
        self.worker.packet.connect(self.on_packet)
        self.worker.start()
    
    def stop_capture(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.terminate()
            self.worker.wait()
        
        self.reset_ui()
        self.status_label.setText("Capture stopped by user")
    
    def capture_finished(self, operation_type, results):
        self.reset_ui()
        self.status_label.setText("Packet capture complete")
        self.save_button.setEnabled(True)
    
    def capture_error(self, error_msg):
        self.reset_ui()
        self.status_label.setText(f"Error: {error_msg}")
        QMessageBox.critical(self, "Capture Error", error_msg)
    
    def update_status(self, message):
        self.status_label.setText(message)
    
    def on_packet(self, info: dict):
        # Append to internal list
        self.captured_packets.append(info)
        # Update table
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        # Fill columns: Time, Source, Destination, Protocol, Length, Info
        self.packet_table.setItem(row, 0, QTableWidgetItem(info.get('time', '')))
        self.packet_table.setItem(row, 1, QTableWidgetItem(info.get('src', '')))
        self.packet_table.setItem(row, 2, QTableWidgetItem(info.get('dst', '')))
        self.packet_table.setItem(row, 3, QTableWidgetItem(info.get('protocol', '')))
        # Length not currently provided; leave blank or N/A
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(info.get('length', ''))))
        self.packet_table.setItem(row, 5, QTableWidgetItem(info.get('info', '')))
        # Update stats
        proto_key = info.get('protocol', 'other').lower()
        total = int(self.stats_labels['total'].text()) + 1
        self.stats_labels['total'].setText(str(total))
        if proto_key in self.stats_labels:
            count = int(self.stats_labels[proto_key].text()) + 1
            self.stats_labels[proto_key].setText(str(count))
        else:
            count = int(self.stats_labels['other'].text()) + 1
            self.stats_labels['other'].setText(str(count))
    
    def packet_selected(self):
        current_row = self.packet_table.currentRow()
        if current_row >= 0 and current_row < len(self.captured_packets):
            packet = self.captured_packets[current_row]
            details = f"""Packet #{current_row + 1}

Source: {packet.get('src', 'N/A')}
Destination: {packet.get('dst', 'N/A')}
Protocol: {packet.get('protocol', 'N/A')}
Length: {packet.get('length', 'N/A')} bytes
Time: {packet.get('time', 'N/A')}

Raw Data:
{packet.get('raw', 'No raw data available')}
"""
            self.packet_details.setPlainText(details)
    
    def clear_results(self):
        self.captured_packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.save_button.setEnabled(False)
        
        # Reset statistics
        for label in self.stats_labels.values():
            label.setText("0")
        
        self.status_label.setText("Results cleared")
    
    def save_capture(self):
        if not self.captured_packets:
            QMessageBox.information(self, "Save", "No packets to save.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Packet Capture", 
            f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.captured_packets, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        for i, packet in enumerate(self.captured_packets):
                            f.write(f"Packet #{i + 1}\n")
                            f.write(f"Time: {packet.get('time', 'N/A')}\n")
                            f.write(f"Source: {packet.get('src', 'N/A')}\n")
                            f.write(f"Destination: {packet.get('dst', 'N/A')}\n")
                            f.write(f"Protocol: {packet.get('protocol', 'N/A')}\n")
                            f.write(f"Length: {packet.get('length', 'N/A')}\n")
                            f.write("-" * 50 + "\n")
                
                QMessageBox.information(self, "Save", f"Capture saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", str(e))
    
    def reset_ui(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)


class VulnerabilityTestTab(QWidget):
    """Tab for vulnerability testing functionality."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Warning message
        warning_frame = QFrame()
        warning_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {ModernStyle.ACCENT_ORANGE};
                color: {ModernStyle.DARK_BG};
                border-radius: 8px;
                padding: 10px;
                margin: 5px;
            }}
        """)
        warning_layout = QHBoxLayout(warning_frame)
        warning_label = QLabel("⚠️ WARNING: Only test on systems you own or have explicit permission to test!")
        warning_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        warning_layout.addWidget(warning_label)
        layout.addWidget(warning_frame)
        
        # Authorization section
        auth_group = QGroupBox("Authorization Required")
        auth_layout = QVBoxLayout()
        
        self.auth_checkbox = QCheckBox("I have explicit written permission to test the target system(s)")
        auth_layout.addWidget(self.auth_checkbox)
        
        self.owner_checkbox = QCheckBox("I own the target system(s)")
        auth_layout.addWidget(self.owner_checkbox)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Test configuration
        config_group = QGroupBox("Test Configuration")
        config_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP address")
        config_layout.addRow("Target IP:", self.target_input)
        
        self.test_type = QComboBox()
        self.test_type.addItems(["Password Strength Test", "Service Enumeration", "Network Stress Test"])
        self.test_type.currentTextChanged.connect(self.test_type_changed)
        config_layout.addRow("Test Type:", self.test_type)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Dynamic configuration area
        self.dynamic_config = QGroupBox("Test-Specific Options")
        self.dynamic_layout = QFormLayout()
        self.dynamic_config.setLayout(self.dynamic_layout)
        layout.addWidget(self.dynamic_config)
        
        self.test_type_changed("Password Strength Test")  # Initialize with default
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🔍 Start Test")
        self.start_button.clicked.connect(self.start_test)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setProperty("class", "danger")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Results area
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.setLayout(layout)
    
    def test_type_changed(self, test_type):
        # Clear existing widgets
        for i in reversed(range(self.dynamic_layout.count())):
            child = self.dynamic_layout.takeAt(i)
            if child.widget():
                child.widget().deleteLater()
        
        if test_type == "Password Strength Test":
            self.port_input = QSpinBox()
            self.port_input.setRange(1, 65535)
            self.port_input.setValue(22)
            self.dynamic_layout.addRow("Port:", self.port_input)
            
            self.service_combo = QComboBox()
            self.service_combo.addItems(["ssh", "ftp", "telnet", "http"])
            self.dynamic_layout.addRow("Service:", self.service_combo)
            
            self.max_attempts = QSpinBox()
            self.max_attempts.setRange(1, 100)
            self.max_attempts.setValue(10)
            self.dynamic_layout.addRow("Max Attempts:", self.max_attempts)
        
        elif test_type == "Service Enumeration":
            self.ports_input = QLineEdit("22,80,443,21,23")
            self.ports_input.setPlaceholderText("Comma-separated ports")
            self.dynamic_layout.addRow("Ports:", self.ports_input)
        
        elif test_type == "Network Stress Test":
            self.stress_port = QSpinBox()
            self.stress_port.setRange(1, 65535)
            self.stress_port.setValue(80)
            self.dynamic_layout.addRow("Port:", self.stress_port)
            
            self.duration = QSpinBox()
            self.duration.setRange(1, 60)
            self.duration.setValue(10)
            self.duration.setSuffix(" seconds")
            self.dynamic_layout.addRow("Duration:", self.duration)
            
            self.rate = QSpinBox()
            self.rate.setRange(1, 50)
            self.rate.setValue(10)
            self.rate.setSuffix(" conn/sec")
            self.dynamic_layout.addRow("Rate:", self.rate)
    
    def start_test(self):
        # Check authorization
        if not (self.auth_checkbox.isChecked() or self.owner_checkbox.isChecked()):
            QMessageBox.warning(
                self, "Authorization Required", 
                "You must confirm authorization before running vulnerability tests."
            )
            return
        
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target IP address.")
            return
        
        # Show additional confirmation dialog
        reply = QMessageBox.question(
            self, "Confirm Test",
            f"Are you absolutely certain you have permission to test {target}?\n\n"
            "Vulnerability testing without permission may be illegal.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_text.clear()
        self.results_text.append("🔒 Authorization confirmed. Starting vulnerability test...\n")
        
        # In a real implementation, this would start the actual test
        QTimer.singleShot(3000, self.mock_test_completed)
    
    def mock_test_completed(self):
        """Mock test completion for demonstration."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        test_type = self.test_type.currentText()
        target = self.target_input.text()
        
        mock_results = f"""
Test completed for {target}

Test Type: {test_type}
Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: 3.2 seconds

Results:
- Target is responsive
- No obvious vulnerabilities detected in this limited test
- Recommend comprehensive security assessment

Note: This is a demonstration. Real implementation would provide actual test results.
"""
        
        self.results_text.append(mock_results)


class AdvancedTestTab(QWidget):
    """Tab for advanced security testing functionality."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Multiple authorization warnings
        warning_frame = QFrame()
        warning_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {ModernStyle.ACCENT_RED};
                color: white;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }}
        """)
        warning_layout = QVBoxLayout(warning_frame)
        
        title_label = QLabel("⚠️ ADVANCED SECURITY TESTING - EXTREME CAUTION REQUIRED ⚠️")
        title_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        warning_text = QLabel(
            "Advanced testing includes aggressive techniques that may:\n"
            "• Trigger security alerts • Consume system resources • Be detected as attacks\n"
            "• Violate terms of service • Be illegal without explicit permission\n\n"
            "ONLY USE ON SYSTEMS YOU OWN OR HAVE EXPLICIT WRITTEN AUTHORIZATION TO TEST!"
        )
        warning_text.setWordWrap(True)
        
        warning_layout.addWidget(title_label)
        warning_layout.addWidget(warning_text)
        layout.addWidget(warning_frame)
        
        # Multi-level authorization
        auth_group = QGroupBox("Multi-Level Authorization Required")
        auth_layout = QVBoxLayout()
        
        self.auth_level1 = QCheckBox("Level 1: I have explicit written permission to perform security testing")
        self.auth_level2 = QCheckBox("Level 2: I understand the risks and potential legal implications")
        self.auth_level3 = QCheckBox("Level 3: I take full responsibility for the use of these tools")
        
        auth_layout.addWidget(self.auth_level1)
        auth_layout.addWidget(self.auth_level2)
        auth_layout.addWidget(self.auth_level3)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Test configuration
        config_group = QGroupBox("Advanced Test Configuration")
        config_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP address")
        config_layout.addRow("Target IP:", self.target_input)
        
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Stealth Scan", "Comprehensive Scan", "Aggressive Scan"])
        config_layout.addRow("Scan Type:", self.scan_type)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QGridLayout()
        
        self.evasion_techniques = QCheckBox("Evasion Techniques")
        self.os_fingerprinting = QCheckBox("OS Fingerprinting")
        self.protocol_fuzzing = QCheckBox("Protocol Fuzzing")
        self.vuln_scanning = QCheckBox("Vulnerability Scanning")
        
        advanced_layout.addWidget(self.evasion_techniques, 0, 0)
        advanced_layout.addWidget(self.os_fingerprinting, 0, 1)
        advanced_layout.addWidget(self.protocol_fuzzing, 1, 0)
        advanced_layout.addWidget(self.vuln_scanning, 1, 1)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("⚡ Start Advanced Test")
        self.start_button.setProperty("class", "danger")
        self.start_button.clicked.connect(self.start_advanced_test)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("🛑 Emergency Stop")
        self.stop_button.setProperty("class", "danger")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.generate_report = QPushButton("📋 Generate Report")
        self.generate_report.setEnabled(False)
        button_layout.addWidget(self.generate_report)
        
        layout.addLayout(button_layout)
        
        # Results area with tree view for detailed results
        results_group = QGroupBox("Advanced Test Results")
        results_layout = QVBoxLayout()
        
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Component", "Status", "Details"])
        
        results_layout.addWidget(self.results_tree)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.setLayout(layout)
    
    def start_advanced_test(self):
        # Check all authorization levels
        if not all([self.auth_level1.isChecked(), self.auth_level2.isChecked(), self.auth_level3.isChecked()]):
            QMessageBox.critical(
                self, "Authorization Required", 
                "All three authorization levels must be confirmed for advanced testing."
            )
            return
        
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target IP address.")
            return
        
        # Final confirmation with scary warning
        reply = QMessageBox.question(
            self, "FINAL CONFIRMATION",
            f"🚨 LAST WARNING 🚨\n\n"
            f"You are about to perform ADVANCED SECURITY TESTING on {target}\n\n"
            f"This may:\n"
            f"• Trigger intrusion detection systems\n"
            f"• Generate security alerts\n"
            f"• Consume significant network/system resources\n"
            f"• Be logged and investigated\n"
            f"• Result in legal action if unauthorized\n\n"
            f"Are you ABSOLUTELY CERTAIN you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_tree.clear()
        self.generate_report.setEnabled(False)
        
        # Add initial status
        root_item = QTreeWidgetItem(self.results_tree)
        root_item.setText(0, f"Advanced Test: {target}")
        root_item.setText(1, "Running")
        root_item.setText(2, f"Started at {datetime.now().strftime('%H:%M:%S')}")
        
        # Mock different test phases
        phases = [
            ("Initial Reconnaissance", "Completed", "Target is responsive"),
            ("Port Scanning", "Completed", "23 open ports discovered"),
            ("Service Enumeration", "Completed", "SSH, HTTP, HTTPS services detected"),
            ("OS Fingerprinting", "Completed", "Linux 4.x detected"),
            ("Vulnerability Assessment", "Completed", "3 potential vulnerabilities found"),
            ("Evasion Testing", "Completed", "Basic IDS evasion successful"),
        ]
        
        for phase, status, details in phases:
            item = QTreeWidgetItem(root_item)
            item.setText(0, phase)
            item.setText(1, status)
            item.setText(2, details)
        
        self.results_tree.expandAll()
        
        # Simulate completion after a delay
        QTimer.singleShot(5000, self.advanced_test_completed)
    
    def advanced_test_completed(self):
        """Mock advanced test completion."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.generate_report.setEnabled(True)
        
        # Update status
        root_item = self.results_tree.topLevelItem(0)
        if root_item:
            root_item.setText(1, "Completed")
            root_item.setText(2, f"Finished at {datetime.now().strftime('%H:%M:%S')}")


class NetGuardianGUI(QMainWindow):
    """Main application window for NetGuardian GUI."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.init_menu()
        self.init_statusbar()
        
        # Apply modern styling
        self.setStyleSheet(ModernStyle.get_stylesheet())
    
    def init_ui(self):
        self.setWindowTitle("NetGuardian - Network Analysis Suite")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 800)
        
        # Central widget with tab layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Header with logo and title
        header_frame = QFrame()
        header_frame.setMaximumHeight(80)
        header_layout = QHBoxLayout(header_frame)
        
        # Title and subtitle
        title_layout = QVBoxLayout()
        
        title_label = QLabel("NetGuardian")
        title_font = QFont("Arial", 24, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: {ModernStyle.ACCENT_BLUE};")
        
        subtitle_label = QLabel("Network Analysis & Security Testing Suite")
        subtitle_font = QFont("Arial", 12)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY};")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        title_layout.addStretch()
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        # Quick stats (placeholder)
        stats_layout = QVBoxLayout()
        stats_layout.addWidget(QLabel("System Status: Ready"))
        stats_layout.addWidget(QLabel("Last Scan: Never"))
        stats_layout.addStretch()
        
        header_layout.addLayout(stats_layout)
        
        layout.addWidget(header_frame)
        
        # Main tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.discovery_tab = HostDiscoveryTab()
        self.scan_tab = PortScanTab()
        self.sniffer_tab = PacketSnifferTab()
        self.vuln_tab = VulnerabilityTestTab()
        self.advanced_tab = AdvancedTestTab()
        
        # Add tabs with icons (using emoji as placeholders)
        self.tab_widget.addTab(self.discovery_tab, "🔍 Host Discovery")
        self.tab_widget.addTab(self.scan_tab, "🎯 Port Scanning")
        self.tab_widget.addTab(self.sniffer_tab, "📡 Packet Capture")
        self.tab_widget.addTab(self.vuln_tab, "🔒 Vulnerability Testing")
        self.tab_widget.addTab(self.advanced_tab, "⚡ Advanced Testing")
        
        layout.addWidget(self.tab_widget)
    
    def init_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Session", self)
        new_action.setShortcut("Ctrl+N")
        file_menu.addAction(new_action)
        
        open_action = QAction("Open Results", self)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)
        
        save_action = QAction("Save Session", self)
        save_action.setShortcut("Ctrl+S")
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(self.show_preferences)
        tools_menu.addAction(preferences_action)
        
        tools_menu.addSeparator()
        
        interface_action = QAction("List Network Interfaces", self)
        tools_menu.addAction(interface_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About NetGuardian", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("Documentation", self)
        help_menu.addAction(docs_action)
    
    def init_statusbar(self):
        self.statusbar = self.statusBar()
        
        # Status message
        self.status_label = QLabel("Ready")
        self.statusbar.addWidget(self.status_label)
        
        # Connection status
        self.statusbar.addPermanentWidget(QLabel("Network: Connected"))
        
        # Current time
        self.time_label = QLabel()
        self.statusbar.addPermanentWidget(self.time_label)
        
        # Update time every second
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        self.update_time()
    
    def update_time(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.setText(current_time)
    
    def show_preferences(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Preferences")
        dialog.setModal(True)
        dialog.resize(400, 300)
        
        layout = QVBoxLayout(dialog)
        
        # Theme selection
        theme_group = QGroupBox("Appearance")
        theme_layout = QVBoxLayout()
        
        dark_theme = QRadioButton("Dark Theme")
        dark_theme.setChecked(True)
        light_theme = QRadioButton("Light Theme")
        
        theme_layout.addWidget(dark_theme)
        theme_layout.addWidget(light_theme)
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        timeout_spin = QSpinBox()
        timeout_spin.setRange(1, 30)
        timeout_spin.setValue(5)
        network_layout.addRow("Default Timeout:", timeout_spin)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec()
    
    def show_about(self):
        about_text = f"""
<h2>NetGuardian Network Analysis Suite</h2>
<p><b>Version:</b> 2.0 GUI Edition</p>
<p><b>Author:</b> Network Security Team</p>

<p>NetGuardian is a comprehensive network analysis and security testing tool 
designed for educational purposes and authorized security analysis.</p>

<h3>Features:</h3>
<ul>
<li>Network Host Discovery</li>
<li>Port Scanning & Service Detection</li>
<li>Packet Capture & Analysis</li>
<li>Vulnerability Testing</li>
<li>Advanced Security Assessment</li>
</ul>

<h3>Legal Notice:</h3>
<p><i>This tool is intended for educational purposes and authorized testing only. 
Use this tool only on networks that you own or have explicit written permission to test.</i></p>

<p style="color: {ModernStyle.ACCENT_BLUE};">Built with PyQt6 and modern UI principles.</p>
"""
        
        QMessageBox.about(self, "About NetGuardian", about_text)
    
    def closeEvent(self, event):
        reply = QMessageBox.question(
            self, "Exit NetGuardian",
            "Are you sure you want to exit NetGuardian?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetGuardian")
    app.setApplicationVersion("2.0")
    
    # Set application icon (if available)
    # app.setWindowIcon(QIcon("path/to/icon.png"))
    
    window = NetGuardianGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
