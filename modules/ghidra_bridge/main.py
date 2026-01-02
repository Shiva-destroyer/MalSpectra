"""
MalSpectra - Ghidra Bridge Module
Main entry point for Ghidra headless analysis integration

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

from core.logger import get_logger
from .bridge import GhidraBridge


console = Console()
logger = get_logger("GhidraBridge")


def display_module_header():
    """Display the module header."""
    header = Text()
    header.append("🔗 ", style="bold cyan")
    header.append("GHIDRA HEADLESS BRIDGE", style="bold cyan")
    header.append(" 🔗", style="bold cyan")
    
    console.print()
    console.print(Panel(
        header,
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 2)
    ))
    console.print()


def configure_ghidra(bridge: GhidraBridge) -> bool:
    """
    Configure Ghidra headless path.
    
    Args:
        bridge: GhidraBridge instance
    
    Returns:
        True if configured successfully
    """
    console.print("[bold yellow]⚙️  Ghidra Configuration[/bold yellow]\n")
    console.print("Please provide the path to Ghidra's analyzeHeadless script.")
    console.print("[dim]Example: /opt/ghidra/support/analyzeHeadless[/dim]")
    console.print("[dim]         C:\\ghidra\\support\\analyzeHeadless.bat[/dim]\n")
    
    path = Prompt.ask("[cyan]Ghidra Headless Path[/cyan]")
    
    if path.lower() in ['exit', 'quit', 'cancel']:
        return False
    
    console.print("\n[dim]Validating path...[/dim]")
    
    if bridge.configure(path):
        console.print("[bold green]✓ Configuration saved successfully[/bold green]\n")
        logger.info(f"Ghidra configured: {path}")
        return True
    else:
        console.print("[bold red]❌ Invalid path or file not found[/bold red]\n")
        logger.error(f"Failed to configure Ghidra: {path}")
        return False


def get_target_file() -> Path:
    """
    Get target file from user.
    
    Returns:
        Path to target file or None
    """
    console.print("[bold yellow]Enter the path to the binary file[/bold yellow]")
    console.print("[dim](Type 'exit' to return to main menu)[/dim]\n")
    
    file_path = Prompt.ask("[cyan]Target File[/cyan]")
    
    if file_path.lower() in ['exit', 'quit', 'q']:
        return None
    
    target = Path(file_path)
    
    if not target.exists():
        console.print(f"\n[bold red]❌ Error: File not found[/bold red]")
        console.print(f"[dim]Path: {file_path}[/dim]\n")
        return None
    
    return target


def display_function_analysis(results: dict):
    """Display function analysis results."""
    console.print()
    
    # Summary panel
    summary = Text()
    summary.append(f"Program: ", style="white")
    summary.append(f"{results['program_name']}\n", style="bold cyan")
    summary.append(f"Functions Analyzed: ", style="white")
    summary.append(f"{results['function_count']}", style="bold green")
    
    console.print(Panel(
        summary,
        title="[bold cyan]═══ ANALYSIS SUMMARY ═══[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    ))
    console.print()
    
    # Functions table
    table = Table(
        title="[bold cyan]FUNCTION ANALYSIS[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        padding=(0, 1)
    )
    
    table.add_column("Function", style="bold yellow", width=30)
    table.add_column("Address", style="white", width=15)
    table.add_column("Size", style="cyan", width=10, justify="right")
    table.add_column("Params", style="green", width=8, justify="center")
    table.add_column("External", style="magenta", width=10, justify="center")
    table.add_column("Called By", style="dim", width=10, justify="center")
    
    # Show first 50 functions
    functions = results.get('functions', [])[:50]
    
    for func in functions:
        name = func['name']
        if len(name) > 28:
            name = name[:25] + "..."
        
        table.add_row(
            name,
            func['address'],
            str(func['size']),
            str(func['parameter_count']),
            "Yes" if func['is_external'] else "No",
            str(len(func['called_by']))
        )
    
    if results['function_count'] > 50:
        console.print(f"[dim]Showing 50 of {results['function_count']} functions[/dim]")
    
    console.print(table)
    console.print()


def display_analysis_menu() -> str:
    """
    Display analysis type selection menu.
    
    Returns:
        Selected analysis type
    """
    console.print("[bold cyan]Select Analysis Type:[/bold cyan]\n")
    console.print("  [1] Function Analysis (recommended)")
    console.print("  [2] String Extraction")
    console.print("  [0] Back to main menu\n")
    
    choice = Prompt.ask("[cyan]Choice[/cyan]", default="1")
    
    if choice == "2":
        return "strings"
    elif choice == "0":
        return "exit"
    else:
        return "functions"


def run():
    """Main entry point for Ghidra Bridge module."""
    try:
        display_module_header()
        
        bridge = GhidraBridge()
        
        # Check if Ghidra is configured
        if not bridge.is_configured():
            console.print("[yellow]⚠️  Ghidra is not configured[/yellow]\n")
            
            if Confirm.ask("[cyan]Would you like to configure it now?[/cyan]"):
                if not configure_ghidra(bridge):
                    console.print("\n[yellow]Configuration cancelled[/yellow]\n")
                    input("\nPress Enter to return to main menu...")
                    return
            else:
                console.print("\n[yellow]Ghidra must be configured to use this module[/yellow]\n")
                input("\nPress Enter to return to main menu...")
                return
        else:
            # Show current configuration
            console.print(f"[dim]Ghidra: {bridge.get_ghidra_path()}[/dim]\n")
        
        # Get target file
        target_file = get_target_file()
        if target_file is None:
            return
        
        # Select analysis type
        analysis_type = display_analysis_menu()
        if analysis_type == "exit":
            return
        
        console.print(f"\n[bold green]✓ Starting analysis:[/bold green] {target_file.name}\n")
        console.print("[dim]This may take several minutes depending on binary size...[/dim]\n")
        
        # Run analysis
        results = bridge.run_analysis(str(target_file), analysis_type)
        
        if results:
            # Display results
            if analysis_type == "functions":
                display_function_analysis(results)
            else:
                console.print(f"\n[green]Strings extracted: {results.get('string_count', 0)}[/green]\n")
            
            # Success message
            console.print(Panel(
                "[bold green]✓ Analysis Complete[/bold green]\n"
                "Ghidra headless analysis completed successfully.",
                title="[bold cyan]═══ SUCCESS ═══[/bold cyan]",
                border_style="green",
                box=box.DOUBLE,
                padding=(1, 2)
            ))
        else:
            console.print("\n[bold red]❌ Analysis failed[/bold red]")
            console.print("[dim]Check logs for details or verify Ghidra configuration[/dim]\n")
    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Analysis interrupted by user[/yellow]\n")
        logger.info("Analysis interrupted by user")
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        console.print(f"\n[bold red]❌ Error:[/bold red] {str(e)}\n")
    
    finally:
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
