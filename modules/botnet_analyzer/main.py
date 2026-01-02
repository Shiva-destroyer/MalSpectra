"""
Botnet Traffic Analyzer - User Interface
Interactive PCAP analysis for C2 traffic detection

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

try:
    from .pcap_engine import PCAPAnalyzer, SCAPY_AVAILABLE
except ImportError:
    SCAPY_AVAILABLE = False


console = Console()


def display_banner():
    """Display module banner"""
    banner = Text()
    banner.append("═══ BOTNET TRAFFIC ANALYZER ═══\n", style="bold cyan")
    banner.append("C2 Communication Detection\n", style="dim")
    banner.append("\nDeveloper: Sai Srujan Murthy\n", style="dim")
    banner.append("Email: saisrujanmurthy@gmail.com", style="dim")
    
    console.print(Panel(banner, border_style="cyan"))
    console.print()


def check_dependencies():
    """Check if scapy is available"""
    if not SCAPY_AVAILABLE:
        console.print("[red]✗ Error:[/red] scapy is not installed\n")
        console.print("Install with:")
        console.print("  [cyan]pip install scapy[/cyan]\n")
        return False
    return True


def get_pcap_file() -> str:
    """Get PCAP file from user"""
    console.print("[bold cyan]Select PCAP File[/bold cyan]\n")
    
    # Look for PCAP files in data directory
    data_dir = Path("data")
    if data_dir.exists():
        pcap_files = list(data_dir.glob("*.pcap")) + list(data_dir.glob("*.pcapng"))
        
        if pcap_files:
            console.print("[dim]Available PCAP files in data/:[/dim]\n")
            for i, pcap in enumerate(pcap_files, 1):
                size_kb = pcap.stat().st_size / 1024
                console.print(f"  [{i}] {pcap.name} ({size_kb:.2f} KB)")
            console.print()
    
    # Get file path
    file_path = console.input("[cyan]Enter PCAP file path:[/cyan] ").strip()
    
    if not file_path:
        return None
    
    # Handle relative paths
    path = Path(file_path)
    if not path.is_absolute():
        path = Path("data") / path
    
    if not path.exists():
        console.print(f"[red]✗[/red] File not found: {path}\n")
        return None
    
    return str(path)


def display_dga_findings(results):
    """Display DGA detection results"""
    data = results['dga_detection']
    
    console.print("\n[bold]1. DGA (Domain Generation Algorithm) Detection[/bold]")
    
    if data['clean']:
        console.print("[green]✓ CLEAN[/green] - No DGA activity detected\n")
    else:
        console.print(f"[red]✗ THREAT DETECTED[/red] - {data['count']} suspicious host(s)\n")
        
        table = Table(title="High-Frequency DNS Activity", border_style="red")
        table.add_column("Source IP", style="cyan")
        table.add_column("Total Queries", justify="right", style="white")
        table.add_column("Queries/Min", justify="right", style="yellow")
        table.add_column("Unique Domains", justify="right", style="white")
        table.add_column("Threat", style="red")
        
        for finding in data['findings']:
            table.add_row(
                finding['ip'],
                str(finding['total_queries']),
                f"{finding['queries_per_minute']:.2f}",
                str(finding['unique_domains']),
                finding['threat_level']
            )
        
        console.print(table)
        
        # Show sample domains
        console.print("\n[dim]Sample domains queried:[/dim]")
        for finding in data['findings']:
            console.print(f"  {finding['ip']}:")
            for domain in finding['sample_domains']:
                console.print(f"    • {domain}")
        console.print()


def display_suspicious_ports(results):
    """Display suspicious port traffic"""
    data = results['suspicious_ports']
    
    console.print("[bold]2. Suspicious Port Detection[/bold]")
    
    if data['clean']:
        console.print("[green]✓ CLEAN[/green] - No suspicious port traffic detected\n")
    else:
        console.print(f"[red]✗ THREAT DETECTED[/red] - {data['count']} suspicious connection(s)\n")
        
        table = Table(title="Malware Port Activity", border_style="red")
        table.add_column("Source IP", style="cyan")
        table.add_column("Destination IP", style="cyan")
        table.add_column("Packets", justify="right", style="white")
        table.add_column("Ports", style="yellow")
        table.add_column("Description", style="white")
        table.add_column("Threat", style="red")
        
        for finding in data['findings']:
            ports_str = ", ".join(str(p) for p in finding['ports'])
            desc_str = ", ".join(finding['port_descriptions'][:2])
            if len(finding['port_descriptions']) > 2:
                desc_str += "..."
            
            threat_style = "red" if finding['threat_level'] == 'CRITICAL' else "yellow"
            
            table.add_row(
                finding['source_ip'],
                finding['destination_ip'],
                str(finding['packet_count']),
                ports_str,
                desc_str,
                f"[{threat_style}]{finding['threat_level']}[/{threat_style}]"
            )
        
        console.print(table)
        console.print()


def display_beacons(results):
    """Display C2 beacon detection results"""
    data = results['beacon_detection']
    
    console.print("[bold]3. C2 Beacon Detection[/bold]")
    
    if data['clean']:
        console.print("[green]✓ CLEAN[/green] - No periodic beaconing detected\n")
    else:
        console.print(f"[red]✗ THREAT DETECTED[/red] - {data['count']} beacon(s) detected\n")
        
        table = Table(title="Periodic C2 Beacons", border_style="red")
        table.add_column("Source IP", style="cyan")
        table.add_column("Destination IP", style="cyan")
        table.add_column("Connections", justify="right", style="white")
        table.add_column("Avg Interval", justify="right", style="yellow")
        table.add_column("Duration", justify="right", style="white")
        table.add_column("Threat", style="red")
        
        for finding in data['findings']:
            table.add_row(
                finding['source_ip'],
                finding['destination_ip'],
                str(finding['connection_count']),
                f"{finding['avg_interval_seconds']:.2f}s",
                f"{finding['total_duration_seconds']:.2f}s",
                finding['threat_level']
            )
        
        console.print(table)
        
        console.print("\n[dim]Periodic connections indicate C2 check-ins[/dim]\n")


def display_overall_threat(results):
    """Display overall threat assessment"""
    threat = results['overall_threat']
    
    if threat == 'CLEAN':
        panel = Panel(
            "[bold green]THREAT LEVEL: CLEAN[/bold green]\n\n"
            "No botnet indicators detected.\n"
            "Network traffic appears normal.",
            title="Threat Intelligence Report",
            border_style="green",
            padding=(1, 2)
        )
    elif threat == 'HIGH':
        panel = Panel(
            "[bold yellow]THREAT LEVEL: HIGH[/bold yellow]\n\n"
            "Suspicious activity detected.\n"
            "Potential C2 communication identified.",
            title="Threat Intelligence Report",
            border_style="yellow",
            padding=(1, 2)
        )
    else:  # CRITICAL
        panel = Panel(
            "[bold red]THREAT LEVEL: CRITICAL[/bold red]\n\n"
            "Active botnet traffic detected!\n"
            "Immediate investigation required.",
            title="Threat Intelligence Report",
            border_style="red",
            padding=(1, 2)
        )
    
    console.print(panel)
    console.print()


def display_recommendations(results):
    """Display security recommendations"""
    threat = results['overall_threat']
    
    if threat != 'CLEAN':
        console.print("[bold cyan]Recommended Actions:[/bold cyan]\n")
        
        if not results['dga_detection']['clean']:
            console.print("  [red]•[/red] DGA Activity Detected:")
            console.print("    → Investigate source hosts for malware infection")
            console.print("    → Block suspicious domains at DNS level")
            console.print("    → Check for known DGA patterns\n")
        
        if not results['suspicious_ports']['clean']:
            console.print("  [red]•[/red] Malware Port Activity:")
            console.print("    → Block suspicious ports at firewall")
            console.print("    → Scan affected hosts for malware")
            console.print("    → Review firewall logs for more connections\n")
        
        if not results['beacon_detection']['clean']:
            console.print("  [red]•[/red] C2 Beaconing Detected:")
            console.print("    → Isolate infected hosts immediately")
            console.print("    → Block destination IPs")
            console.print("    → Analyze malware samples on infected hosts\n")
        
        console.print("  [cyan]•[/cyan] General recommendations:")
        console.print("    → Run full antivirus scan on affected systems")
        console.print("    → Check IOCs against threat intelligence feeds")
        console.print("    → Review firewall and IDS/IPS logs")
        console.print("    → Consider network segmentation\n")


def display_statistics(results):
    """Display analysis statistics"""
    console.print("[bold cyan]Analysis Statistics:[/bold cyan]\n")
    console.print(f"  • Total Packets Analyzed: {results['total_packets']:,}")
    console.print(f"  • DGA Indicators: {results['dga_detection']['count']}")
    console.print(f"  • Suspicious Port Connections: {results['suspicious_ports']['count']}")
    console.print(f"  • C2 Beacons: {results['beacon_detection']['count']}")
    console.print(f"  • Overall Threat Level: {results['overall_threat']}\n")


def run():
    """Main entry point for botnet analyzer"""
    display_banner()
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Get PCAP file
    pcap_file = get_pcap_file()
    if not pcap_file:
        console.print("[yellow]Operation cancelled[/yellow]")
        return
    
    console.print(f"\n[green]✓[/green] Selected file: {pcap_file}\n")
    
    # Initialize analyzer
    try:
        analyzer = PCAPAnalyzer()
        console.print("[cyan]Initializing PCAP analyzer...[/cyan]")
        console.print("[green]✓[/green] Analyzer ready\n")
        
        # Analyze PCAP with progress bar
        console.print("[cyan]Analyzing network traffic...[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task1 = progress.add_task("Loading PCAP file...", total=None)
            task2 = progress.add_task("Detecting DGA activity...", total=None)
            task3 = progress.add_task("Scanning for suspicious ports...", total=None)
            task4 = progress.add_task("Analyzing beacon patterns...", total=None)
            
            results = analyzer.analyze_pcap(pcap_file)
            
            progress.update(task1, completed=True)
            progress.update(task2, completed=True)
            progress.update(task3, completed=True)
            progress.update(task4, completed=True)
        
        console.print("\n[green]✓[/green] Analysis complete\n")
        console.print("═" * 70)
        console.print()
        
        # Display results
        display_statistics(results)
        console.print("═" * 70)
        
        display_dga_findings(results)
        console.print("─" * 70)
        
        display_suspicious_ports(results)
        console.print("─" * 70)
        
        display_beacons(results)
        console.print("═" * 70)
        console.print()
        
        # Overall assessment
        display_overall_threat(results)
        display_recommendations(results)
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {str(e)}\n")
        return


if __name__ == "__main__":
    run()
