"""
MalSpectra - Trojan Detection System Interface
Interactive heuristic-based RAT detection scanner

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
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: 'rich' library is required. Install with: pip install rich")
    sys.exit(1)

try:
    from .heuristics import HeuristicScanner
except ImportError:
    from heuristics import HeuristicScanner


console = Console()


def display_banner():
    """Display module banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║         TROJAN DETECTION SYSTEM - MODULE 11                 ║
║           Heuristic-Based RAT Behavior Analysis              ║
╚══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def get_target_file() -> Path:
    """Get target file from user."""
    console.print("\n[bold cyan]Target File Selection:[/bold cyan]\n")
    
    # Check data directory for samples
    data_dir = Path("data")
    if data_dir.exists():
        samples = list(data_dir.glob("**/*.exe")) + list(data_dir.glob("**/*.dll"))
        
        if samples:
            console.print("[yellow]Available samples in data/:[/yellow]")
            for i, sample in enumerate(samples[:10], 1):
                size_mb = sample.stat().st_size / (1024 * 1024)
                console.print(f"  {i}. {sample.name} ({size_mb:.2f} MB)")
            
            console.print(f"\n[yellow]Or enter custom file path[/yellow]")
            choice = console.input("\nSelect file [1-10 or path]: ").strip()
            
            if choice.isdigit() and 1 <= int(choice) <= len(samples):
                return samples[int(choice) - 1]
    
    # Manual path entry
    file_path = console.input("\nEnter file path: ").strip()
    return Path(file_path)


def display_file_info(file_path: Path):
    """Display basic file information."""
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        return False
    
    stat_info = file_path.stat()
    size_mb = stat_info.st_size / (1024 * 1024)
    
    table = Table(title="[bold cyan]File Information[/bold cyan]", 
                  show_header=False, box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("File Name", file_path.name)
    table.add_row("File Path", str(file_path.absolute()))
    table.add_row("File Size", f"{size_mb:.2f} MB ({stat_info.st_size:,} bytes)")
    table.add_row("Extension", file_path.suffix or "None")
    
    console.print("\n")
    console.print(table)
    return True


def display_import_findings(findings: List[Dict]):
    """Display suspicious import findings."""
    if not findings:
        console.print("\n[green]✓ No suspicious import patterns detected[/green]")
        return
    
    table = Table(title="[bold cyan]Suspicious API Import Analysis[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Behavior", style="yellow", justify="left")
    table.add_column("Description", style="white", justify="left")
    table.add_column("APIs Detected", style="cyan", justify="left")
    table.add_column("Score", style="red", justify="right")
    table.add_column("Severity", style="red", justify="center")
    
    for finding in findings:
        if 'error' not in finding:
            apis_str = ", ".join(finding['detected_apis'][:3])
            if len(finding['detected_apis']) > 3:
                apis_str += f" +{len(finding['detected_apis'])-3} more"
            
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'yellow',
                'MEDIUM': 'cyan',
                'LOW': 'green'
            }.get(finding['severity'], 'white')
            
            table.add_row(
                finding['behavior'].replace('_', ' ').title(),
                finding['description'],
                apis_str,
                str(finding['score']),
                f"[{severity_color}]{finding['severity']}[/{severity_color}]"
            )
    
    console.print("\n")
    console.print(table)


def display_string_findings(findings: List[Dict]):
    """Display suspicious string findings."""
    if not findings:
        console.print("\n[green]✓ No suspicious strings detected[/green]")
        return
    
    table = Table(title="[bold cyan]Suspicious String Analysis[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Category", style="yellow", justify="left")
    table.add_column("Description", style="white", justify="left")
    table.add_column("Matches", style="cyan", justify="right")
    table.add_column("Examples", style="dim white", justify="left")
    table.add_column("Score", style="red", justify="right")
    
    for finding in findings:
        if 'error' not in finding:
            examples = "\n".join(finding['matches'][:3])
            if len(finding['matches']) > 3:
                examples += f"\n... +{len(finding['matches'])-3} more"
            
            table.add_row(
                finding['category'].replace('_', ' ').title(),
                finding['description'],
                str(finding['match_count']),
                examples,
                str(finding['score'])
            )
    
    console.print("\n")
    console.print(table)


def display_entropy_findings(findings: Dict):
    """Display entropy analysis findings."""
    if 'error' in findings:
        console.print(f"\n[red]Entropy scan error: {findings['error']}[/red]")
        return
    
    entropy_val = findings['entropy']
    assessment = findings['assessment']
    score = findings.get('score', 0)
    
    # Create entropy bar visualization
    bar_length = 40
    filled = int((entropy_val / 8.0) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    # Color based on entropy
    if entropy_val >= 7.5:
        color = "red"
    elif entropy_val >= 7.0:
        color = "yellow"
    elif entropy_val >= 6.5:
        color = "cyan"
    else:
        color = "green"
    
    console.print(Panel(
        f"[bold white]Shannon Entropy:[/bold white] [{color}]{entropy_val:.4f}[/{color}] / 8.0\n\n"
        f"[{color}]{bar}[/{color}]\n\n"
        f"[bold white]Assessment:[/bold white] {assessment}\n"
        f"[bold white]Score:[/bold white] [red]{score}[/red]",
        title="[bold cyan]Entropy Analysis[/bold cyan]",
        border_style=color
    ))


def display_pe_findings(findings: List[Dict]):
    """Display PE characteristic findings."""
    if not findings or (len(findings) == 1 and 'error' in findings[0]):
        return
    
    if findings and findings[0].get('info'):
        console.print(f"\n[yellow]Info: {findings[0]['info']}[/yellow]")
        return
    
    table = Table(title="[bold cyan]PE File Characteristics[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Characteristic", style="yellow", justify="left")
    table.add_column("Description", style="white", justify="left")
    table.add_column("Score", style="red", justify="right")
    
    for finding in findings:
        if 'characteristic' in finding:
            table.add_row(
                finding['characteristic'],
                finding['description'],
                str(finding['score'])
            )
    
    if table.row_count > 0:
        console.print("\n")
        console.print(table)


def display_overall_assessment(results: Dict):
    """Display overall threat assessment."""
    score = results['total_score']
    assessment = results['assessment']
    threat_level = results['threat_level']
    
    # Color based on threat level
    color_map = {
        'CRITICAL': 'red',
        'HIGH': 'yellow',
        'MEDIUM': 'cyan',
        'LOW': 'blue',
        'SAFE': 'green'
    }
    color = color_map.get(threat_level, 'white')
    
    # Score bar
    bar_length = 50
    filled = int((score / 100) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    console.print("\n")
    console.print(Panel(
        f"[bold white]Suspicion Score:[/bold white] [{color}]{score}[/{color}] / 100\n\n"
        f"[{color}]{bar}[/{color}]\n\n"
        f"[bold white]Threat Level:[/bold white] [{color}]{threat_level}[/{color}]\n\n"
        f"[bold white]Assessment:[/bold white]\n{assessment}",
        title=f"[bold {color}]Overall Threat Assessment[/bold {color}]",
        border_style=color
    ))


def display_score_breakdown(results: Dict):
    """Display score breakdown by category."""
    categories = []
    
    if results['import_findings']:
        import_score = sum(f.get('score', 0) for f in results['import_findings'] 
                          if 'error' not in f)
        categories.append(("Suspicious Imports", import_score))
    
    if results['string_findings']:
        string_score = sum(f.get('score', 0) for f in results['string_findings'] 
                          if 'error' not in f)
        categories.append(("Suspicious Strings", string_score))
    
    if results['entropy_findings']:
        entropy_score = results['entropy_findings'].get('score', 0)
        categories.append(("High Entropy", entropy_score))
    
    if results['pe_findings']:
        pe_score = sum(f.get('score', 0) for f in results['pe_findings'] 
                      if 'score' in f)
        if pe_score > 0:
            categories.append(("PE Characteristics", pe_score))
    
    if not categories:
        return
    
    table = Table(title="[bold cyan]Score Breakdown[/bold cyan]", 
                  show_header=True, header_style="bold magenta", box=box.ROUNDED)
    
    table.add_column("Category", style="cyan", justify="left")
    table.add_column("Score", style="white", justify="right")
    table.add_column("Percentage", style="yellow", justify="right")
    
    for category, score in categories:
        percentage = (score / results['total_score'] * 100) if results['total_score'] > 0 else 0
        table.add_row(category, str(score), f"{percentage:.1f}%")
    
    table.add_row("[bold]TOTAL", f"[bold]{results['total_score']}", "[bold]100.0%")
    
    console.print("\n")
    console.print(table)


def display_recommendations(results: Dict):
    """Display security recommendations based on findings."""
    threat_level = results['threat_level']
    
    if threat_level == "CRITICAL":
        recommendations = (
            "[bold white]IMMEDIATE ACTIONS REQUIRED:[/bold white]\n\n"
            "[red]1. ISOLATE SYSTEM IMMEDIATELY[/red]\n"
            "   • Disconnect from network\n"
            "   • Do not execute the file\n"
            "   • Quarantine the file\n\n"
            "[red]2. INCIDENT RESPONSE[/red]\n"
            "   • Alert security team\n"
            "   • Preserve evidence\n"
            "   • Begin forensic analysis\n\n"
            "[red]3. MALWARE ANALYSIS[/red]\n"
            "   • Submit to malware sandbox\n"
            "   • Run in isolated VM only\n"
            "   • Document all behaviors\n\n"
            "[red]4. THREAT HUNTING[/red]\n"
            "   • Scan network for IoCs\n"
            "   • Check for lateral movement\n"
            "   • Review logs for anomalies"
        )
        border_color = "red"
    
    elif threat_level == "HIGH":
        recommendations = (
            "[bold white]SECURITY MEASURES RECOMMENDED:[/bold white]\n\n"
            "[yellow]1. Do Not Execute[/yellow]\n"
            "   • File shows multiple RAT indicators\n"
            "   • Requires further analysis\n\n"
            "[yellow]2. Enhanced Analysis[/yellow]\n"
            "   • Submit to VirusTotal\n"
            "   • Run in sandbox environment\n"
            "   • Perform memory forensics\n\n"
            "[yellow]3. Preventive Measures[/yellow]\n"
            "   • Update antivirus signatures\n"
            "   • Enable behavioral monitoring\n"
            "   • Review access controls"
        )
        border_color = "yellow"
    
    elif threat_level in ["MEDIUM", "LOW"]:
        recommendations = (
            "[bold white]PRECAUTIONARY STEPS:[/bold white]\n\n"
            "[cyan]1. Verify Source[/cyan]\n"
            "   • Confirm file legitimacy\n"
            "   • Check digital signatures\n"
            "   • Validate file hash\n\n"
            "[cyan]2. Additional Scanning[/cyan]\n"
            "   • Run multiple AV scans\n"
            "   • Use online scanners\n"
            "   • Monitor execution if needed\n\n"
            "[cyan]3. Best Practices[/cyan]\n"
            "   • Maintain backups\n"
            "   • Use least privilege\n"
            "   • Keep systems updated"
        )
        border_color = "cyan"
    
    else:  # SAFE
        recommendations = (
            "[bold white]File appears clean, but remember:[/bold white]\n\n"
            "[green]1. Stay Vigilant[/green]\n"
            "   • Heuristics not 100% accurate\n"
            "   • New threats emerge daily\n\n"
            "[green]2. Security Hygiene[/green]\n"
            "   • Keep AV updated\n"
            "   • Regular system scans\n"
            "   • Practice safe browsing\n\n"
            "[green]3. Defense in Depth[/green]\n"
            "   • Multiple security layers\n"
            "   • Network monitoring\n"
            "   • User education"
        )
        border_color = "green"
    
    console.print(Panel(
        recommendations,
        title="[bold white]Security Recommendations[/bold white]",
        border_style=border_color
    ))


def run_scan():
    """Main scanning workflow."""
    display_banner()
    
    # Get target file
    file_path = get_target_file()
    
    # Display file info
    if not display_file_info(file_path):
        return
    
    console.print("\n[bold cyan]Starting heuristic scan...[/bold cyan]")
    
    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Analyzing file...", total=4)
        
        scanner = HeuristicScanner(file_path)
        
        progress.update(task, advance=1, description="[cyan]Scanning imports...")
        results = scanner.perform_full_scan()
        
        progress.update(task, advance=3, description="[cyan]Scan complete!")
    
    # Display results
    console.print("\n[bold green]✓ Scan complete![/bold green]\n")
    
    display_import_findings(results['import_findings'])
    display_string_findings(results['string_findings'])
    display_entropy_findings(results['entropy_findings'])
    display_pe_findings(results['pe_findings'])
    
    display_overall_assessment(results)
    display_score_breakdown(results)
    display_recommendations(results)
    
    console.print("\n[dim]Note: Heuristic analysis provides indicators, not definitive proof.[/dim]\n")


def run():
    """Entry point for module execution."""
    try:
        run_scan()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error during scan:[/bold red] {str(e)}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    run()
