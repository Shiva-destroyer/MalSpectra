"""
MalSpectra - Worm Propagation Simulator Engine
Implements network-based malware spread simulation using SIR model

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import random
from typing import Dict, List, Tuple, Set
from collections import defaultdict

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


class NetworkTopology:
    """
    Network topology generator for various network structures.
    Supports random, scale-free, and small-world networks.
    """
    
    @staticmethod
    def create_network(nodes: int = 100, topology: str = "random") -> 'nx.Graph':
        """
        Create a network topology for simulation.
        
        Args:
            nodes: Number of nodes in the network
            topology: Type of network ('random', 'scale_free', 'small_world')
            
        Returns:
            NetworkX graph object
        """
        if not NETWORKX_AVAILABLE:
            raise ImportError("networkx is required for network simulation")
        
        if topology == "random":
            # Erdős-Rényi random graph
            # p = probability of edge creation
            p = 0.05  # 5% connection probability
            return nx.erdos_renyi_graph(nodes, p)
        
        elif topology == "scale_free":
            # Barabási-Albert scale-free network
            # m = number of edges to attach from new node
            m = 3
            return nx.barabasi_albert_graph(nodes, m)
        
        elif topology == "small_world":
            # Watts-Strogatz small-world network
            k = 6  # Each node connected to k nearest neighbors
            p = 0.1  # Probability of rewiring
            return nx.watts_strogatz_graph(nodes, k, p)
        
        else:
            raise ValueError(f"Unknown topology: {topology}")
    
    @staticmethod
    def get_network_stats(graph: 'nx.Graph') -> Dict:
        """
        Calculate network statistics.
        
        Args:
            graph: NetworkX graph
            
        Returns:
            Dictionary with network metrics
        """
        stats = {
            'nodes': graph.number_of_nodes(),
            'edges': graph.number_of_edges(),
            'avg_degree': sum(dict(graph.degree()).values()) / graph.number_of_nodes(),
            'density': nx.density(graph),
            'is_connected': nx.is_connected(graph),
        }
        
        if nx.is_connected(graph):
            stats['diameter'] = nx.diameter(graph)
            stats['avg_path_length'] = nx.average_shortest_path_length(graph)
        else:
            stats['diameter'] = "N/A (disconnected)"
            stats['avg_path_length'] = "N/A (disconnected)"
        
        return stats


class WormSimulator:
    """
    SIR (Susceptible-Infected-Recovered) model for worm propagation.
    
    States:
    - Susceptible (S): Vulnerable to infection
    - Infected (I): Currently infected and spreading
    - Recovered (R): Immune/patched (optional)
    """
    
    def __init__(self, graph: 'nx.Graph'):
        """
        Initialize simulator with network topology.
        
        Args:
            graph: NetworkX graph representing the network
        """
        self.graph = graph
        self.node_states = {}  # node_id -> 'S', 'I', or 'R'
        self.infection_time = {}  # node_id -> step when infected
        self.history = []  # List of state snapshots
        
        # Initialize all nodes as susceptible
        for node in self.graph.nodes():
            self.node_states[node] = 'S'
    
    def infect_initial_node(self, node_id: int = None):
        """
        Infect the initial patient zero node.
        
        Args:
            node_id: Node to infect (random if None)
        """
        if node_id is None:
            node_id = random.choice(list(self.graph.nodes()))
        
        self.node_states[node_id] = 'I'
        self.infection_time[node_id] = 0
        
        # Record initial state
        self._record_state(0)
    
    def simulate_step(self, step: int, infection_rate: float, recovery_rate: float = 0.0):
        """
        Simulate one time step of worm propagation.
        
        Args:
            step: Current simulation step
            infection_rate: Probability of transmission (0.0-1.0)
            recovery_rate: Probability of recovery/patching (0.0-1.0)
        """
        # Get currently infected nodes
        infected_nodes = [n for n, state in self.node_states.items() if state == 'I']
        
        # Attempt to infect neighbors
        new_infections = []
        for infected in infected_nodes:
            neighbors = list(self.graph.neighbors(infected))
            
            for neighbor in neighbors:
                if self.node_states[neighbor] == 'S':
                    # Attempt infection based on infection_rate
                    if random.random() < infection_rate:
                        new_infections.append(neighbor)
        
        # Apply new infections
        for node in new_infections:
            self.node_states[node] = 'I'
            self.infection_time[node] = step
        
        # Recovery phase (optional)
        if recovery_rate > 0:
            recoveries = []
            for infected in infected_nodes:
                if random.random() < recovery_rate:
                    recoveries.append(infected)
            
            for node in recoveries:
                self.node_states[node] = 'R'
        
        # Record state
        self._record_state(step)
    
    def simulate_full(self, max_steps: int, infection_rate: float, 
                      recovery_rate: float = 0.0, entry_node: int = None) -> List[Dict]:
        """
        Run full simulation until equilibrium or max steps.
        
        Args:
            max_steps: Maximum simulation steps
            infection_rate: Probability of transmission
            recovery_rate: Probability of recovery
            entry_node: Initial infected node
            
        Returns:
            List of state dictionaries for each step
        """
        # Reset simulation
        self.node_states = {n: 'S' for n in self.graph.nodes()}
        self.infection_time = {}
        self.history = []
        
        # Infect initial node
        self.infect_initial_node(entry_node)
        
        # Run simulation
        for step in range(1, max_steps + 1):
            self.simulate_step(step, infection_rate, recovery_rate)
            
            # Check for equilibrium (no infected nodes)
            infected_count = sum(1 for s in self.node_states.values() if s == 'I')
            if infected_count == 0:
                break
        
        return self.history
    
    def _record_state(self, step: int):
        """Record current state snapshot."""
        state = {
            'step': step,
            'susceptible': sum(1 for s in self.node_states.values() if s == 'S'),
            'infected': sum(1 for s in self.node_states.values() if s == 'I'),
            'recovered': sum(1 for s in self.node_states.values() if s == 'R'),
            'total': len(self.node_states)
        }
        self.history.append(state)
    
    def get_infection_statistics(self) -> Dict:
        """
        Calculate final infection statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_infected = sum(1 for n in self.infection_time)
        infection_times = list(self.infection_time.values())
        
        stats = {
            'total_nodes': len(self.node_states),
            'total_infected': total_infected,
            'infection_rate': total_infected / len(self.node_states),
            'avg_infection_time': sum(infection_times) / len(infection_times) if infection_times else 0,
            'peak_infected': max(h['infected'] for h in self.history) if self.history else 0,
        }
        
        # Find peak step
        if self.history:
            peak_step = max(self.history, key=lambda x: x['infected'])
            stats['peak_step'] = peak_step['step']
        
        return stats
    
    def get_most_critical_nodes(self, top_n: int = 5) -> List[Tuple[int, float]]:
        """
        Identify nodes with highest betweenness centrality (critical for spread).
        
        Args:
            top_n: Number of critical nodes to return
            
        Returns:
            List of (node_id, centrality_score) tuples
        """
        centrality = nx.betweenness_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]


class WormAnalyzer:
    """
    Analyzes worm propagation patterns and generates insights.
    """
    
    @staticmethod
    def compare_topologies(nodes: int = 100, steps: int = 20, 
                          infection_rate: float = 0.3) -> Dict[str, Dict]:
        """
        Compare worm spread across different network topologies.
        
        Args:
            nodes: Number of nodes
            steps: Simulation steps
            infection_rate: Transmission probability
            
        Returns:
            Dictionary mapping topology to statistics
        """
        if not NETWORKX_AVAILABLE:
            return {}
        
        results = {}
        topologies = ['random', 'scale_free', 'small_world']
        
        for topo in topologies:
            graph = NetworkTopology.create_network(nodes, topo)
            simulator = WormSimulator(graph)
            simulator.simulate_full(steps, infection_rate)
            results[topo] = simulator.get_infection_statistics()
        
        return results
    
    @staticmethod
    def calculate_r0(infection_rate: float, avg_degree: float, 
                    recovery_rate: float = 0.0) -> float:
        """
        Calculate basic reproduction number (R0).
        
        R0 = (infection_rate * avg_degree) / recovery_rate
        
        R0 > 1: Epidemic spreads
        R0 < 1: Epidemic dies out
        
        Args:
            infection_rate: Transmission probability
            avg_degree: Average connections per node
            recovery_rate: Recovery probability
            
        Returns:
            R0 value
        """
        if recovery_rate == 0:
            # Without recovery, R0 is effectively infinite if infection_rate > 0
            return float('inf') if infection_rate > 0 else 0
        
        return (infection_rate * avg_degree) / recovery_rate
