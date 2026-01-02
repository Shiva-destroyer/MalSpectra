"""
MalSpectra - Worm Propagation Simulator Interface
Interactive worm spread simulation with network analysis

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import sys
from pathlib import Path
from typing import Dict, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: 'rich' library is required. Install with: pip install rich")
    sys.exit(1)

try:
    from .simulator import NetworkTopology, WormSimulator, WormAnalyzer, NETWORKX_AVAILABLE
except ImportError:
    # Fallback for direct execution
    from simulator import NetworkTopology, WormSimulator, WormAnalyzer, NETWORKX_AVAILABLE


console = Console()


def display_banner():
    """Display module banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║          WORM PROPAGATION SIMULATOR - MODULE 10             ║
║                  Network-Based Malware Spread                ║
╚══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def check_dependencies() -> bool:
    """Check if networkx is available."""
    if not NETWORKX_AVAILABLE:
        console.print(Panel(
            "[bold red]ERROR: NetworkX library not found[/bold red]\n\n"
            "This module requires NetworkX for network simulation.\n\n"
            "[cyan]Installation:[/cyan]\n"
            "  pip install networkx\n"
            "  or\n"
            "  pip install -r requirements.txt",
            title="[red]Missing Dependency[/red]",
            border_style="red"
        ))
        return False
    return True


def get_simulation_parameters() -> Dict:
    """Get simulation parameters from user."""
    console.print("\n[bold cyan]Simulation Parameters:[/bold cyan]\n")
    
    # Network size
    console.print("[yellow]Network Size:[/yellow]")
    console.print("  1. Small (50 nodes)")
    console.print("  2. Medium (100 nodes)")
    console.print("  3. Large (200 nodes)")
    size_choice = console.input("\nSelect network size [1-3]: ").strip()
    
    nodes_map = {'1': 50, '2': 100, '3': 200}
    nodes = nodes_map.get(size_choice, 100)
    
    # Topology
    console.print("\n[yellow]Network Topology:[/yellow]")
    console.print("  1. Random (Erdős-Rényi)")
    console.print("  2. Scale-Free (Barabási-Albert)")
    console.print("  3. Small-World (Watts-Strogatz)")
    topo_choice = console.input("\nSelect topology [1-3]: ").strip()
    
    topo_map = {'1': 'random', '2': 'scale_free', '3': 'small_world'}
    topology = topo_map.get(topo_choice, 'random')
    
    # Infection rate
    console.print("\n[yellow]Infection Rate:[/yellow]")
    console.print("  1. Low (10%)")
    console.print("  2. Medium (30%)")
    console.print("  3. High (50%)")
    console.print("  4. Very High (70%)")
    rate_choice = console.input("\nSelect infection rate [1-4]: ").strip()
    
    rate_map = {'1': 0.1, '2': 0.3, '3': 0.5, '4': 0.7}
    infection_rate = rate_map.get(rate_choice, 0.3)
    
    # Recovery rate
    console.print("\n[yellow]Recovery/Patching Rate:[/yellow]")
    console.print("  1. None (0%)")
    console.print("  2. Low (5%)")
    console.print("  3. Medium (10%)")
    recovery_choice = console.input("\nSelect recovery rate [1-3]: ").strip()
    
    recovery_map = {'1': 0.0, '2': 0.05, '3': 0.1}
    recovery_rate = recovery_map.get(recovery_choice, 0.0)
    
    # Simulation steps
    steps = 30
    
    return {
        'nodes': nodes,
        'topology': topology,
        'infection_rate': infection_rate,
        'recovery_rate': recovery_rate,
        'steps': steps
    }


def display_network_stats(stats: Dict):
    """Display network topology statistics."""
    table = Table(title="[bold cyan]Network Topology Statistics[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="white", justify="right")
    
    table.add_row("Total Nodes", str(stats['nodes']))
    table.add_row("Total Edges", str(stats['edges']))
    table.add_row("Average Degree", f"{stats['avg_degree']:.2f}")
    table.add_row("Network Density", f"{stats['density']:.4f}")
    table.add_row("Connected", "Yes" if stats['is_connected'] else "No")
    table.add_row("Diameter", str(stats['diameter']))
    table.add_row("Avg Path Length", 
                  f"{stats['avg_path_length']:.2f}" if isinstance(stats['avg_path_length'], float) 
                  else str(stats['avg_path_length']))
    
    console.print("\n")
    console.print(table)


def display_simulation_progress(history: List[Dict], params: Dict):
    """Display simulation progress with rich formatting."""
    console.print("\n[bold cyan]═══ Simulation Progress ═══[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Running simulation...", total=len(history))
        
        for i, state in enumerate(history):
            progress.update(task, advance=1, 
                          description=f"[cyan]Step {state['step']}: "
                                    f"{state['infected']} infected, "
                                    f"{state['susceptible']} susceptible")
            
            # Display every 5 steps
            if i % 5 == 0 or i == len(history) - 1:
                console.print(
                    f"  [yellow]Step {state['step']:2d}:[/yellow] "
                    f"[red]I:{state['infected']:3d}[/red] | "
                    f"[green]S:{state['susceptible']:3d}[/green] | "
                    f"[blue]R:{state['recovered']:3d}[/blue]"
                )


def display_infection_statistics(stats: Dict):
    """Display final infection statistics."""
    table = Table(title="[bold cyan]Infection Statistics[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="white", justify="right")
    
    table.add_row("Total Nodes", str(stats['total_nodes']))
    table.add_row("Total Infected", f"{stats['total_infected']}")
    table.add_row("Infection Rate", f"{stats['infection_rate']*100:.1f}%")
    table.add_row("Peak Infected", f"{stats['peak_infected']}")
    table.add_row("Peak Step", f"{stats.get('peak_step', 'N/A')}")
    table.add_row("Avg Infection Time", f"{stats['avg_infection_time']:.2f} steps")
    
    console.print("\n")
    console.print(table)
    
    # Visual assessment
    infection_pct = stats['infection_rate'] * 100
    if infection_pct > 80:
        severity = "CRITICAL"
        color = "red"
        description = "Worm achieved near-total network penetration"
    elif infection_pct > 50:
        severity = "HIGH"
        color = "yellow"
        description = "Worm infected majority of network"
    elif infection_pct > 20:
        severity = "MEDIUM"
        color = "cyan"
        description = "Worm achieved moderate spread"
    else:
        severity = "LOW"
        color = "green"
        description = "Worm contained with limited spread"
    
    console.print(Panel(
        f"[bold white]Spread Severity:[/bold white] [{color}]{severity}[/{color}]\n"
        f"[white]{description}[/white]",
        title="[yellow]Assessment[/yellow]",
        border_style=color
    ))


def display_critical_nodes(critical_nodes: List):
    """Display most critical nodes for worm spread."""
    table = Table(title="[bold cyan]Critical Network Nodes[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Rank", style="cyan", justify="center")
    table.add_column("Node ID", style="yellow", justify="center")
    table.add_column("Centrality Score", style="white", justify="right")
    table.add_column("Impact", style="red", justify="left")
    
    for i, (node_id, score) in enumerate(critical_nodes, 1):
        if score > 0.1:
            impact = "🔴 CRITICAL"
        elif score > 0.05:
            impact = "🟡 HIGH"
        else:
            impact = "🟢 MEDIUM"
        
        table.add_row(str(i), str(node_id), f"{score:.4f}", impact)
    
    console.print("\n")
    console.print(table)
    console.print("\n[cyan]Note:[/cyan] Nodes with high betweenness centrality are key to worm propagation.")


def display_recommendations():
    """Display security recommendations."""
    console.print(Panel(
        "[bold white]Network Defense Recommendations:[/bold white]\n\n"
        "[cyan]1. Segment Critical Systems[/cyan]\n"
        "   • Isolate high-centrality nodes\n"
        "   • Use network segmentation and VLANs\n"
        "   • Implement zero-trust architecture\n\n"
        "[cyan]2. Rapid Patching Strategy[/cyan]\n"
        "   • Prioritize critical nodes for patches\n"
        "   • Automate security updates\n"
        "   • Maintain patch management system\n\n"
        "[cyan]3. Network Monitoring[/cyan]\n"
        "   • Deploy IDS/IPS on critical links\n"
        "   • Monitor unusual connection patterns\n"
        "   • Implement anomaly detection\n\n"
        "[cyan]4. Incident Response[/cyan]\n"
        "   • Prepare isolation procedures\n"
        "   • Have rollback/recovery plans\n"
        "   • Practice containment drills\n\n"
        "[cyan]5. Topology Optimization[/cyan]\n"
        "   • Reduce unnecessary connections\n"
        "   • Implement network access control\n"
        "   • Regular topology audits",
        title="[bold green]Security Best Practices[/bold green]",
        border_style="green"
    ))


def run_simulation():
    """Main simulation workflow."""
    display_banner()
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Get parameters
    params = get_simulation_parameters()
    
    console.print("\n[bold cyan]Creating network topology...[/bold cyan]")
    
    # Create network
    graph = NetworkTopology.create_network(params['nodes'], params['topology'])
    network_stats = NetworkTopology.get_network_stats(graph)
    display_network_stats(network_stats)
    
    # Calculate R0
    r0 = WormAnalyzer.calculate_r0(
        params['infection_rate'], 
        network_stats['avg_degree'],
        params['recovery_rate']
    )
    
    console.print(f"\n[yellow]Basic Reproduction Number (R0):[/yellow] ", end="")
    if r0 == float('inf'):
        console.print("[red]∞ (No recovery - epidemic will spread)[/red]")
    elif r0 > 1:
        console.print(f"[red]{r0:.2f} (Epidemic will spread)[/red]")
    else:
        console.print(f"[green]{r0:.2f} (Epidemic will die out)[/green]")
    
    # Run simulation
    console.print("\n[bold cyan]Starting worm propagation simulation...[/bold cyan]")
    simulator = WormSimulator(graph)
    history = simulator.simulate_full(
        params['steps'],
        params['infection_rate'],
        params['recovery_rate']
    )
    
    # Display progress
    display_simulation_progress(history, params)
    
    # Display statistics
    stats = simulator.get_infection_statistics()
    display_infection_statistics(stats)
    
    # Display critical nodes
    critical_nodes = simulator.get_most_critical_nodes(5)
    display_critical_nodes(critical_nodes)
    
    # Display recommendations
    display_recommendations()
    
    console.print("\n[bold green]✓ Simulation complete![/bold green]\n")


def run():
    """Entry point for module execution."""
    try:
        run_simulation()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Simulation interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error during simulation:[/bold red] {str(e)}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    run()
