"""
Rootkit Analysis Suite - User Interface
Interactive system integrity checking

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .detector import RootkitDetector


console = Console()


def display_banner():
    """Display module banner"""
    banner = Text()
    banner.append("═══ ROOTKIT ANALYSIS SUITE ═══\n", style="bold cyan")
    banner.append("System Integrity Scanner\n", style="dim")
    banner.append("\nDeveloper: Sai Srujan Murthy\n", style="dim")
    banner.append("Email: saisrujanmurthy@gmail.com", style="dim")
    
    console.print(Panel(banner, border_style="cyan"))
    console.print()


def check_root_privileges():
    """Check if running as root (recommended)"""
    if os.geteuid() != 0:
        console.print("[yellow]⚠[/yellow]  Not running as root")
        console.print("[dim]Some checks may be limited without root privileges[/dim]\n")
        return False
    else:
        console.print("[green]✓[/green] Running as root\n")
        return True


def display_hidden_processes(results):
    """Display hidden processes report"""
    data = results['hidden_processes']
    
    if data['clean']:
        console.print("[green]✓ CLEAN[/green] - No hidden processes detected\n")
    else:
        console.print(f"[red]✗ INFECTED[/red] - {data['count']} hidden process(es) detected\n")
        
        if data['findings']:
            table = Table(title="Hidden Processes", border_style="red")
            table.add_column("PID", style="cyan", justify="right")
            table.add_column("Command Line", style="white")
            table.add_column("Threat Level", style="red")
            
            for finding in data['findings']:
                if 'error' not in finding:
                    table.add_row(
                        str(finding['pid']),
                        finding.get('cmdline', 'Unknown'),
                        finding.get('threat_level', 'UNKNOWN')
                    )
            
            console.print(table)
            console.print()


def display_ld_preload(results):
    """Display LD_PRELOAD hooks report"""
    data = results['ld_preload']
    
    suspicious_count = len([f for f in data['findings'] if f.get('suspicious', False)])
    
    if data['count'] == 0:
        console.print("[green]✓ CLEAN[/green] - No LD_PRELOAD hooks detected\n")
    elif suspicious_count > 0:
        console.print(f"[red]✗ SUSPICIOUS[/red] - {suspicious_count} suspicious hook(s) detected\n")
        
        table = Table(title="LD_PRELOAD Hooks", border_style="red")
        table.add_column("Location", style="cyan")
        table.add_column("Library", style="white")
        table.add_column("Threat Level", style="red")
        table.add_column("Details", style="dim")
        
        for finding in data['findings']:
            if 'error' not in finding:
                threat_level = finding.get('threat_level', 'UNKNOWN')
                threat_style = "red" if threat_level in ['CRITICAL', 'HIGH'] else "yellow"
                
                table.add_row(
                    finding.get('location', 'Unknown'),
                    finding.get('library', 'Unknown'),
                    f"[{threat_style}]{threat_level}[/{threat_style}]",
                    finding.get('reason', 'Suspicious pattern detected' if finding.get('suspicious') else '')
                )
        
        console.print(table)
        console.print()
    else:
        console.print(f"[yellow]⚠ INFO[/yellow] - {data['count']} LD_PRELOAD hook(s) found (non-suspicious)\n")
        
        for finding in data['findings']:
            if 'error' not in finding:
                console.print(f"  • {finding.get('library', 'Unknown')} ({finding.get('location', 'Unknown')})")
        console.print()


def display_promiscuous_mode(results):
    """Display promiscuous network interfaces report"""
    data = results['promiscuous_mode']
    
    promisc_count = len([f for f in data['findings'] if f.get('status') == 'PROMISCUOUS'])
    
    if promisc_count == 0:
        console.print("[green]✓ CLEAN[/green] - No promiscuous interfaces detected\n")
    else:
        console.print(f"[red]✗ SUSPICIOUS[/red] - {promisc_count} promiscuous interface(s) detected\n")
        
        table = Table(title="Promiscuous Network Interfaces", border_style="red")
        table.add_column("Interface", style="cyan")
        table.add_column("Status", style="red")
        table.add_column("Threat Level", style="yellow")
        table.add_column("Description", style="dim")
        
        for finding in data['findings']:
            if finding.get('status') == 'PROMISCUOUS':
                table.add_row(
                    finding.get('interface', 'Unknown'),
                    finding.get('status', 'UNKNOWN'),
                    finding.get('threat_level', 'UNKNOWN'),
                    finding.get('description', '')
                )
        
        console.print(table)
        console.print()


def display_overall_status(results):
    """Display overall system status"""
    status = results['overall_status']
    
    if status == 'CLEAN':
        panel = Panel(
            "[bold green]SYSTEM STATUS: CLEAN[/bold green]\n\n"
            "No rootkit indicators detected.\n"
            "System appears to be healthy.",
            title="System Integrity Report",
            border_style="green",
            padding=(1, 2)
        )
    elif status == 'SUSPICIOUS':
        panel = Panel(
            "[bold yellow]SYSTEM STATUS: SUSPICIOUS[/bold yellow]\n\n"
            "Potential rootkit indicators detected.\n"
            "Further investigation recommended.",
            title="System Integrity Report",
            border_style="yellow",
            padding=(1, 2)
        )
    else:  # INFECTED
        panel = Panel(
            "[bold red]SYSTEM STATUS: INFECTED[/bold red]\n\n"
            "Rootkit activity detected!\n"
            "Immediate action required.",
            title="System Integrity Report",
            border_style="red",
            padding=(1, 2)
        )
    
    console.print(panel)
    console.print()


def display_recommendations(results):
    """Display security recommendations"""
    status = results['overall_status']
    
    if status != 'CLEAN':
        console.print("[bold cyan]Recommended Actions:[/bold cyan]\n")
        
        if not results['hidden_processes']['clean']:
            console.print("  [red]•[/red] Investigate hidden processes immediately")
            console.print("    → Use: ps aux, top, lsof -p <PID>")
            console.print("    → Check: /proc/<PID>/exe, /proc/<PID>/maps\n")
        
        if any(f.get('suspicious', False) for f in results['ld_preload']['findings']):
            console.print("  [yellow]•[/yellow] Review LD_PRELOAD hooks")
            console.print("    → Examine: /etc/ld.so.preload")
            console.print("    → Check library authenticity with: ldd, strings\n")
        
        if not results['promiscuous_mode']['clean']:
            console.print("  [yellow]•[/yellow] Investigate promiscuous interfaces")
            console.print("    → Check for sniffing tools: tcpdump, wireshark")
            console.print("    → Review: netstat, ss, lsof -i\n")
        
        console.print("  [cyan]•[/cyan] General recommendations:")
        console.print("    → Run rkhunter or chkrootkit")
        console.print("    → Check system logs: /var/log/syslog, /var/log/auth.log")
        console.print("    → Verify system files: rpm -Va or debsums")
        console.print("    → Consider reinstalling from known good media\n")


def run():
    """Main entry point for rootkit analysis"""
    display_banner()
    
    # Check privileges
    is_root = check_root_privileges()
    
    # Initialize detector
    console.print("[cyan]Initializing rootkit detector...[/cyan]")
    detector = RootkitDetector()
    console.print("[green]✓[/green] Detector ready\n")
    
    # Run scans
    with console.status("[bold cyan]Scanning system for rootkit indicators...", spinner="dots"):
        results = detector.run_all_checks()
    
    console.print("[green]✓[/green] Scan complete\n")
    console.print("═" * 60)
    console.print()
    
    # Display results
    console.print("[bold cyan]═══ SCAN RESULTS ═══[/bold cyan]\n")
    
    console.print("[bold]1. Hidden Processes Check[/bold]")
    display_hidden_processes(results)
    
    console.print("[bold]2. LD_PRELOAD Hooks Check[/bold]")
    display_ld_preload(results)
    
    console.print("[bold]3. Promiscuous Mode Check[/bold]")
    display_promiscuous_mode(results)
    
    console.print("═" * 60)
    console.print()
    
    # Overall status
    display_overall_status(results)
    
    # Recommendations
    display_recommendations(results)


if __name__ == "__main__":
    run()
