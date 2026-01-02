"""
MalSpectra - Malware Packer/Unpacker Interface
Interactive binary packing and overlay management

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
    from .upx_handler import UPXHandler
    from .overlay_stripper import OverlayStripper
except ImportError:
    from upx_handler import UPXHandler
    from overlay_stripper import OverlayStripper


console = Console()


def display_banner():
    """Display module banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║       MALWARE PACKER/UNPACKER - MODULE 12                   ║
║          Binary Packing & Overlay Management                 ║
╚══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def display_main_menu():
    """Display main menu options."""
    console.print("\n[bold cyan]Main Menu:[/bold cyan]\n")
    console.print("  [yellow]1.[/yellow] Pack Binary (UPX)")
    console.print("  [yellow]2.[/yellow] Unpack Binary (UPX)")
    console.print("  [yellow]3.[/yellow] Check UPX Status")
    console.print("  [yellow]4.[/yellow] Strip Overlay")
    console.print("  [yellow]5.[/yellow] Extract Overlay")
    console.print("  [yellow]6.[/yellow] Analyze Overlay")
    console.print("  [yellow]7.[/yellow] UPX Installation Help")
    console.print("  [yellow]0.[/yellow] Exit")


def get_target_file(operation: str = "analyze") -> Path:
    """Get target file from user."""
    console.print(f"\n[bold cyan]Select file for {operation}:[/bold cyan]\n")
    
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


def check_upx_status():
    """Check and display UPX installation status."""
    upx = UPXHandler()
    
    if upx.is_upx_available():
        version = upx.get_upx_version()
        
        console.print(Panel(
            f"[bold green]✓ UPX is installed and available[/bold green]\n\n"
            f"[white]Version:[/white] {version}\n"
            f"[white]Location:[/white] {upx.upx_path}",
            title="[green]UPX Status[/green]",
            border_style="green"
        ))
    else:
        console.print(Panel(
            "[bold red]✗ UPX is not installed[/bold red]\n\n"
            "[white]UPX (Ultimate Packer for eXecutables) is required for\n"
            "packing and unpacking operations.[/white]\n\n"
            "[cyan]Select option 7 for installation instructions.[/cyan]",
            title="[red]UPX Not Found[/red]",
            border_style="red"
        ))


def pack_binary_workflow():
    """Workflow for packing a binary."""
    console.print("\n[bold cyan]═══ UPX Binary Packing ═══[/bold cyan]")
    
    upx = UPXHandler()
    if not upx.is_upx_available():
        console.print("\n[red]Error: UPX is not installed.[/red]")
        console.print("[cyan]Select option 7 for installation instructions.[/cyan]\n")
        return
    
    # Get input file
    input_file = get_target_file("packing")
    
    if not input_file.exists():
        console.print(f"\n[red]Error: File not found: {input_file}[/red]\n")
        return
    
    # Check if already packed
    if upx.is_upx_packed(str(input_file)):
        console.print(f"\n[yellow]Warning: {input_file.name} is already UPX packed.[/yellow]")
        console.print("[cyan]Use option 2 to unpack it first.[/cyan]\n")
        return
    
    # Get compression level
    console.print("\n[yellow]Compression Level:[/yellow]")
    console.print("  1-3: Fast (low compression)")
    console.print("  4-6: Balanced")
    console.print("  7-9: Best (high compression, slower)")
    
    level_input = console.input("\nSelect level [1-9, default 9]: ").strip()
    compression_level = int(level_input) if level_input.isdigit() and 1 <= int(level_input) <= 9 else 9
    
    # Get output file
    output_file = str(input_file) + ".packed"
    
    # Perform packing
    console.print(f"\n[cyan]Packing {input_file.name} with compression level {compression_level}...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Compressing...", total=100)
        
        success, message = upx.pack_binary(str(input_file), output_file, compression_level)
        
        progress.update(task, completed=100)
    
    if success:
        console.print(f"\n[bold green]✓ {message}[/bold green]")
        console.print(f"\n[cyan]Output file:[/cyan] {output_file}\n")
    else:
        console.print(f"\n[bold red]✗ {message}[/bold red]\n")


def unpack_binary_workflow():
    """Workflow for unpacking a binary."""
    console.print("\n[bold cyan]═══ UPX Binary Unpacking ═══[/bold cyan]")
    
    upx = UPXHandler()
    if not upx.is_upx_available():
        console.print("\n[red]Error: UPX is not installed.[/red]")
        console.print("[cyan]Select option 7 for installation instructions.[/cyan]\n")
        return
    
    # Get input file
    input_file = get_target_file("unpacking")
    
    if not input_file.exists():
        console.print(f"\n[red]Error: File not found: {input_file}[/red]\n")
        return
    
    # Check if packed
    if not upx.is_upx_packed(str(input_file)):
        console.print(f"\n[yellow]Warning: {input_file.name} does not appear to be UPX packed.[/yellow]")
        proceed = console.input("Try unpacking anyway? [y/N]: ").strip().lower()
        if proceed != 'y':
            return
    
    # Get output file
    output_file = str(input_file) + ".unpacked"
    
    # Perform unpacking
    console.print(f"\n[cyan]Unpacking {input_file.name}...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Decompressing...", total=100)
        
        success, message = upx.unpack_binary(str(input_file), output_file)
        
        progress.update(task, completed=100)
    
    if success:
        console.print(f"\n[bold green]✓ {message}[/bold green]")
        console.print(f"\n[cyan]Output file:[/cyan] {output_file}\n")
    else:
        console.print(f"\n[bold red]✗ {message}[/bold red]\n")


def strip_overlay_workflow():
    """Workflow for stripping PE overlay."""
    console.print("\n[bold cyan]═══ PE Overlay Stripping ═══[/bold cyan]")
    
    # Get input file
    input_file = get_target_file("overlay stripping")
    
    if not input_file.exists():
        console.print(f"\n[red]Error: File not found: {input_file}[/red]\n")
        return
    
    # Check if PE file
    if not OverlayStripper.is_pe_file(str(input_file)):
        console.print(f"\n[red]Error: {input_file.name} is not a valid PE file.[/red]\n")
        return
    
    # Detect overlay
    console.print(f"\n[cyan]Analyzing {input_file.name}...[/cyan]")
    has_overlay, info = OverlayStripper.detect_overlay(str(input_file))
    
    if 'error' in info:
        console.print(f"\n[red]Error: {info['error']}[/red]\n")
        return
    
    if not has_overlay:
        console.print(f"\n[green]✓ No overlay detected in {input_file.name}[/green]\n")
        return
    
    # Display overlay info
    console.print(Panel(
        f"[white]File Size:[/white] {info['file_size']:,} bytes\n"
        f"[white]PE Size:[/white] {info['calculated_pe_size']:,} bytes\n"
        f"[white]Overlay Size:[/white] {info['overlay_size']:,} bytes\n"
        f"[white]Sections:[/white] {len(info['sections'])}",
        title="[yellow]Overlay Detected[/yellow]",
        border_style="yellow"
    ))
    
    # Confirm stripping
    proceed = console.input("\nStrip overlay? [y/N]: ").strip().lower()
    if proceed != 'y':
        console.print("[yellow]Operation cancelled.[/yellow]\n")
        return
    
    # Strip overlay
    output_file = str(input_file) + ".stripped"
    
    success, message = OverlayStripper.strip_overlay(str(input_file), output_file, backup=True)
    
    if success:
        console.print(f"\n[bold green]✓ {message}[/bold green]\n")
    else:
        console.print(f"\n[bold red]✗ {message}[/bold red]\n")


def extract_overlay_workflow():
    """Workflow for extracting PE overlay."""
    console.print("\n[bold cyan]═══ PE Overlay Extraction ═══[/bold cyan]")
    
    # Get input file
    input_file = get_target_file("overlay extraction")
    
    if not input_file.exists():
        console.print(f"\n[red]Error: File not found: {input_file}[/red]\n")
        return
    
    # Extract overlay
    console.print(f"\n[cyan]Extracting overlay from {input_file.name}...[/cyan]")
    
    output_file = str(input_file) + ".overlay"
    success, message = OverlayStripper.extract_overlay(str(input_file), output_file)
    
    if success:
        console.print(f"\n[bold green]✓ {message}[/bold green]\n")
    else:
        console.print(f"\n[bold red]✗ {message}[/bold red]\n")


def analyze_overlay_workflow():
    """Workflow for analyzing PE overlay."""
    console.print("\n[bold cyan]═══ PE Overlay Analysis ═══[/bold cyan]")
    
    # Get input file
    input_file = get_target_file("overlay analysis")
    
    if not input_file.exists():
        console.print(f"\n[red]Error: File not found: {input_file}[/red]\n")
        return
    
    # Analyze
    console.print(f"\n[cyan]Analyzing {input_file.name}...[/cyan]\n")
    analysis = OverlayStripper.analyze_overlay(str(input_file))
    
    if 'error' in analysis:
        console.print(f"[red]Error: {analysis['error']}[/red]\n")
        return
    
    if not analysis.get('has_overlay'):
        console.print("[green]✓ No overlay detected in this file.[/green]\n")
        return
    
    # Display results
    table = Table(title="[bold cyan]Overlay Analysis Results[/bold cyan]", 
                  show_header=False, box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("File Size", f"{analysis['file_size']:,} bytes")
    table.add_row("PE Size", f"{analysis['calculated_pe_size']:,} bytes")
    table.add_row("Overlay Size", f"{analysis['overlay_size']:,} bytes")
    table.add_row("Overlay %", f"{(analysis['overlay_size']/analysis['file_size']*100):.1f}%")
    table.add_row("Sections", str(len(analysis['sections'])))
    
    if 'overlay_entropy' in analysis:
        table.add_row("Overlay Entropy", f"{analysis['overlay_entropy']:.4f}")
        table.add_row("Assessment", analysis['overlay_assessment'])
    
    if 'detected_formats' in analysis:
        table.add_row("Detected Format", ", ".join(analysis['detected_formats']))
    
    console.print(table)
    
    # Display sections
    if analysis['sections']:
        console.print("\n[bold cyan]PE Sections:[/bold cyan]")
        sec_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        sec_table.add_column("Name", style="yellow")
        sec_table.add_column("Raw Size", style="white", justify="right")
        sec_table.add_column("Raw Address", style="cyan", justify="right")
        sec_table.add_column("End Offset", style="white", justify="right")
        
        for section in analysis['sections']:
            sec_table.add_row(
                section['name'],
                f"{section['raw_size']:,}",
                f"{section['raw_address']:,}",
                f"{section['end_offset']:,}"
            )
        
        console.print(sec_table)
    
    console.print()


def display_upx_help():
    """Display UPX installation instructions."""
    upx = UPXHandler()
    instructions = upx.get_installation_instructions()
    
    console.print(Panel(
        instructions,
        title="[bold cyan]UPX Installation Instructions[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("\n[yellow]After installation, restart this module to use UPX features.[/yellow]\n")


def run_packer_unpacker():
    """Main packer/unpacker workflow."""
    display_banner()
    
    while True:
        display_main_menu()
        
        choice = console.input("\n[bold cyan]Select option:[/bold cyan] ").strip()
        
        if choice == '1':
            pack_binary_workflow()
        elif choice == '2':
            unpack_binary_workflow()
        elif choice == '3':
            check_upx_status()
        elif choice == '4':
            strip_overlay_workflow()
        elif choice == '5':
            extract_overlay_workflow()
        elif choice == '6':
            analyze_overlay_workflow()
        elif choice == '7':
            display_upx_help()
        elif choice == '0':
            console.print("\n[cyan]Exiting...[/cyan]\n")
            break
        else:
            console.print("\n[red]Invalid option. Please try again.[/red]\n")


def run():
    """Entry point for module execution."""
    try:
        run_packer_unpacker()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Operation interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    run()
