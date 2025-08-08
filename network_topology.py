#!/usr/bin/env python3
"""
NetGuardian Network Topology Visualization Module
Provides network mapping and visualization capabilities.
"""

import logging
import json
from typing import Dict, List, Any, Optional, Tuple
import ipaddress
from collections import defaultdict
import math

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    print("Warning: NetworkX/Matplotlib not available. Install with: pip install networkx matplotlib")

class NetworkTopologyMapper:
    """
    A class for creating and visualizing network topology maps.
    """
    
    def __init__(self):
        """Initialize the NetworkTopologyMapper."""
        self.logger = logging.getLogger(__name__)
        self.graph = nx.Graph() if HAS_NETWORKX else None
        self.node_positions = {}
        self.node_data = {}
        
    def build_topology_from_scan(self, scan_results: List[Dict[str, Any]], 
                                 gateway_ip: Optional[str] = None) -> nx.Graph:
        """
        Build a network topology graph from scan results.
        
        Args:
            scan_results: List of host discovery and port scan results
            gateway_ip: Optional gateway/router IP for hierarchical layout
            
        Returns:
            NetworkX graph object representing the topology
        """
        if not HAS_NETWORKX:
            raise ImportError("NetworkX is required for topology mapping")
            
        self.graph.clear()
        
        # Add gateway/router as central node if provided
        if gateway_ip:
            self.graph.add_node(gateway_ip, 
                              node_type='gateway',
                              label=f"Gateway\n{gateway_ip}",
                              color='red',
                              size=1000)
            self.node_data[gateway_ip] = {'type': 'gateway', 'services': []}
        
        # Add discovered hosts
        for host in scan_results:
            ip = host.get('ip', '')
            if not ip:
                continue
                
            # Determine node type based on services
            node_type = self._determine_node_type(host)
            services = host.get('services', [])
            open_ports = host.get('ports', [])
            
            # Add node with attributes
            self.graph.add_node(ip,
                              node_type=node_type,
                              label=self._create_node_label(host),
                              color=self._get_node_color(node_type),
                              size=self._get_node_size(node_type),
                              mac=host.get('mac', ''),
                              hostname=host.get('hostname', ''),
                              os=host.get('os', 'Unknown'),
                              services=services,
                              ports=open_ports)
            
            self.node_data[ip] = {
                'type': node_type,
                'services': services,
                'ports': open_ports,
                'mac': host.get('mac', ''),
                'os': host.get('os', 'Unknown')
            }
            
            # Connect to gateway if exists
            if gateway_ip and ip != gateway_ip:
                self.graph.add_edge(gateway_ip, ip)
        
        # Detect and add connections between hosts based on network segments
        self._detect_network_segments()
        
        return self.graph
    
    def _determine_node_type(self, host: Dict[str, Any]) -> str:
        """Determine the type of network node based on services."""
        services = host.get('services', [])
        ports = host.get('ports', [])
        
        # Check for specific service patterns
        service_names = [s.get('service', '').lower() for s in ports]
        
        if any('http' in s or 'https' in s for s in service_names):
            return 'server'
        elif any('ssh' in s or 'rdp' in s or 'vnc' in s for s in service_names):
            return 'workstation'
        elif any('smtp' in s or 'pop' in s or 'imap' in s for s in service_names):
            return 'mail_server'
        elif any('dns' in s for s in service_names):
            return 'dns_server'
        elif any('ftp' in s or 'smb' in s for s in service_names):
            return 'file_server'
        elif any('sql' in s or 'mysql' in s or 'postgres' in s for s in service_names):
            return 'database'
        elif len(ports) > 10:
            return 'server'
        else:
            return 'host'
    
    def _create_node_label(self, host: Dict[str, Any]) -> str:
        """Create a label for a network node."""
        ip = host.get('ip', 'Unknown')
        hostname = host.get('hostname', '')
        
        if hostname and hostname != ip:
            return f"{hostname}\n{ip}"
        return ip
    
    def _get_node_color(self, node_type: str) -> str:
        """Get color for node based on type."""
        colors = {
            'gateway': '#ff4444',
            'server': '#4444ff',
            'workstation': '#44ff44',
            'mail_server': '#ff8844',
            'dns_server': '#8844ff',
            'file_server': '#44ffff',
            'database': '#ff44ff',
            'host': '#888888'
        }
        return colors.get(node_type, '#cccccc')
    
    def _get_node_size(self, node_type: str) -> int:
        """Get size for node based on type."""
        sizes = {
            'gateway': 1000,
            'server': 800,
            'database': 800,
            'mail_server': 700,
            'dns_server': 700,
            'file_server': 700,
            'workstation': 500,
            'host': 400
        }
        return sizes.get(node_type, 400)
    
    def _detect_network_segments(self):
        """Detect and connect nodes in the same network segment."""
        if not self.graph.nodes():
            return
            
        # Group nodes by subnet
        subnets = defaultdict(list)
        for node in self.graph.nodes():
            try:
                ip = ipaddress.ip_address(node)
                # Assume /24 subnet for simplicity
                subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnets[str(subnet)].append(node)
            except:
                continue
        
        # Connect nodes in the same subnet (but limit connections for clarity)
        for subnet, nodes in subnets.items():
            if len(nodes) > 1:
                # Create a mesh for small subnets, hub-spoke for large ones
                if len(nodes) <= 5:
                    # Full mesh for small groups
                    for i, node1 in enumerate(nodes):
                        for node2 in nodes[i+1:]:
                            if not self.graph.has_edge(node1, node2):
                                self.graph.add_edge(node1, node2, 
                                                  connection_type='subnet',
                                                  weight=0.5)
                else:
                    # Hub-spoke for larger groups (find most connected node)
                    hub = max(nodes, key=lambda n: len(list(self.graph.neighbors(n))))
                    for node in nodes:
                        if node != hub and not self.graph.has_edge(hub, node):
                            self.graph.add_edge(hub, node,
                                              connection_type='subnet',
                                              weight=0.5)
    
    def visualize_topology(self, title: str = "Network Topology",
                          layout: str = "spring",
                          figsize: Tuple[int, int] = (12, 8),
                          save_path: Optional[str] = None) -> Optional[Figure]:
        """
        Visualize the network topology.
        
        Args:
            title: Title for the visualization
            layout: Layout algorithm ('spring', 'circular', 'shell', 'hierarchical')
            figsize: Figure size as (width, height)
            save_path: Optional path to save the figure
            
        Returns:
            Matplotlib figure object
        """
        if not HAS_NETWORKX or not self.graph:
            return None
            
        fig, ax = plt.subplots(figsize=figsize)
        
        # Calculate positions based on layout
        if layout == "spring":
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(self.graph)
        elif layout == "shell":
            # Group nodes by type for shell layout
            shells = self._group_nodes_by_type()
            pos = nx.shell_layout(self.graph, shells)
        elif layout == "hierarchical":
            pos = self._hierarchical_layout()
        else:
            pos = nx.spring_layout(self.graph)
        
        self.node_positions = pos
        
        # Draw edges
        edge_colors = []
        edge_widths = []
        for edge in self.graph.edges(data=True):
            if edge[2].get('connection_type') == 'subnet':
                edge_colors.append('#cccccc')
                edge_widths.append(0.5)
            else:
                edge_colors.append('#666666')
                edge_widths.append(1.0)
        
        nx.draw_networkx_edges(self.graph, pos, 
                               edge_color=edge_colors,
                               width=edge_widths,
                               alpha=0.5,
                               ax=ax)
        
        # Draw nodes
        for node_type in set(nx.get_node_attributes(self.graph, 'node_type').values()):
            node_list = [n for n, d in self.graph.nodes(data=True) 
                        if d.get('node_type') == node_type]
            if node_list:
                nx.draw_networkx_nodes(self.graph, pos,
                                      nodelist=node_list,
                                      node_color=[self._get_node_color(node_type)],
                                      node_size=self._get_node_size(node_type),
                                      alpha=0.8,
                                      ax=ax)
        
        # Draw labels
        labels = nx.get_node_attributes(self.graph, 'label')
        nx.draw_networkx_labels(self.graph, pos, labels,
                               font_size=8,
                               font_weight='bold',
                               ax=ax)
        
        # Add legend
        legend_elements = []
        for node_type in ['gateway', 'server', 'workstation', 'database', 
                         'mail_server', 'dns_server', 'file_server', 'host']:
            if any(d.get('node_type') == node_type for n, d in self.graph.nodes(data=True)):
                legend_elements.append(plt.Line2D([0], [0], 
                                                 marker='o', 
                                                 color='w',
                                                 markerfacecolor=self._get_node_color(node_type),
                                                 markersize=10,
                                                 label=node_type.replace('_', ' ').title()))
        
        ax.legend(handles=legend_elements, loc='upper right')
        
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.axis('off')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            self.logger.info(f"Topology visualization saved to {save_path}")
        
        return fig
    
    def _group_nodes_by_type(self) -> List[List[str]]:
        """Group nodes by type for shell layout."""
        groups = defaultdict(list)
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('node_type', 'host')
            groups[node_type].append(node)
        
        # Order groups by importance
        order = ['gateway', 'server', 'database', 'workstation', 'host']
        shells = []
        for node_type in order:
            if node_type in groups:
                shells.append(groups[node_type])
        
        return shells
    
    def _hierarchical_layout(self) -> Dict[str, Tuple[float, float]]:
        """Create a hierarchical layout with gateway at top."""
        pos = {}
        
        # Find gateway node
        gateway = None
        for node, data in self.graph.nodes(data=True):
            if data.get('node_type') == 'gateway':
                gateway = node
                break
        
        if gateway:
            # Use tree layout with gateway as root
            tree = nx.bfs_tree(self.graph, gateway)
            pos = nx.spring_layout(tree)
        else:
            # Fall back to spring layout
            pos = nx.spring_layout(self.graph)
        
        return pos
    
    def export_topology(self, format: str = "json", 
                       filepath: Optional[str] = None) -> str:
        """
        Export topology data in various formats.
        
        Args:
            format: Export format ('json', 'graphml', 'gexf')
            filepath: Optional file path to save
            
        Returns:
            Exported data as string
        """
        if not HAS_NETWORKX or not self.graph:
            return ""
        
        if format == "json":
            data = nx.node_link_data(self.graph)
            result = json.dumps(data, indent=2)
        elif format == "graphml":
            from io import StringIO
            buffer = StringIO()
            nx.write_graphml(self.graph, buffer)
            result = buffer.getvalue()
        elif format == "gexf":
            from io import StringIO
            buffer = StringIO()
            nx.write_gexf(self.graph, buffer)
            result = buffer.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(result)
            self.logger.info(f"Topology exported to {filepath}")
        
        return result
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """
        Calculate network topology statistics.
        
        Returns:
            Dictionary containing various network metrics
        """
        if not HAS_NETWORKX or not self.graph:
            return {}
        
        stats = {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'connected_components': nx.number_connected_components(self.graph),
            'density': nx.density(self.graph),
            'average_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes() if self.graph.number_of_nodes() > 0 else 0
        }
        
        # Node type distribution
        node_types = nx.get_node_attributes(self.graph, 'node_type')
        type_counts = defaultdict(int)
        for node_type in node_types.values():
            type_counts[node_type] += 1
        stats['node_types'] = dict(type_counts)
        
        # Find critical nodes (high betweenness centrality)
        if self.graph.number_of_nodes() > 0:
            centrality = nx.betweenness_centrality(self.graph)
            sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            stats['critical_nodes'] = sorted_nodes[:5]  # Top 5 critical nodes
        
        return stats
