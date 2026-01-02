"""
MalSpectra - Reverse Engineering Module
Main entry point for the Advanced Malware Reverse Engineering Suite

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text
from rich import box

from core.logger import get_logger
from .pe_analyzer import PEAnalyzer
from .disassembler import Disassembler


console = Console()
logger = get_logger("ReverseEngineering")


def display_module_header():
    """Display the module header."""
    header = Text()
    header.append("🔬 ", style="bold cyan")
    header.append("ADVANCED MALWARE REVERSE ENGINEERING SUITE", style="bold cyan")
    header.append(" 🔬", style="bold cyan")
    
    console.print()
    console.print(Panel(
        header,
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 2)
    ))
    console.print()


def get_target_file() -> Path:
    """
    Prompt user for target file path and validate.
    
    Returns:
        Path object to the target file
    
    Raises:
        SystemExit: If user cancels or file is invalid
    """
    console.print("[bold yellow]Enter the path to the PE file to analyze[/bold yellow]")
    console.print("[dim](Type 'exit' to return to main menu)[/dim]\n")
    
    file_path = Prompt.ask("[cyan]Target File[/cyan]")
    
    if file_path.lower() in ['exit', 'quit', 'q']:
        logger.info("User cancelled file selection")
        console.print("\n[yellow]Operation cancelled[/yellow]\n")
        return None
    
    target = Path(file_path)
    
    if not target.exists():
        logger.error(f"File not found: {file_path}")
        console.print(f"\n[bold red]❌ Error: File not found[/bold red]")
        console.print(f"[dim]Path: {file_path}[/dim]\n")
        return None
    
    if not target.is_file():
        logger.error(f"Not a file: {file_path}")
        console.print(f"\n[bold red]❌ Error: Path is not a file[/bold red]\n")
        return None
    
    logger.info(f"Target file selected: {file_path}")
    return target


def display_file_info(analyzer: PEAnalyzer):
    """Display basic file information."""
    file_info = analyzer.get_file_info()
    
    table = Table(
        title="[bold cyan]FILE INFORMATION[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=False,
        padding=(0, 1)
    )
    
    table.add_column("Property", style="bold yellow", width=20)
    table.add_column("Value", style="white")
    
    table.add_row("Filename", file_info['filename'])
    table.add_row("Size", f"{file_info['size']:,} bytes")
    table.add_row("Path", str(file_info['path']))
    
    console.print(table)
    console.print()


def display_headers(analyzer: PEAnalyzer):
    """Display PE headers analysis."""
    headers = analyzer.analyze_headers()
    
    # File Header Table
    table = Table(
        title="[bold cyan]PE HEADERS ANALYSIS[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        padding=(0, 1)
    )
    
    table.add_column("Header", style="bold magenta", width=25)
    table.add_column("Property", style="bold yellow", width=25)
    table.add_column("Value", style="white", width=40)
    
    # DOS Header
    table.add_row("DOS Header", "Magic", headers['dos_header']['magic'])
    table.add_row("", "PE Offset", headers['dos_header']['lfanew'])
    
    # File Header
    table.add_row("File Header", "Machine", f"{headers['file_header']['machine']} ({headers['file_header']['machine_type']})")
    table.add_row("", "Sections", str(headers['file_header']['number_of_sections']))
    table.add_row("", "Timestamp", str(headers['file_header']['timestamp']))
    
    # Optional Header
    table.add_row("Optional Header", "Architecture", headers['optional_header']['architecture'])
    table.add_row("", "Entry Point", headers['optional_header']['entry_point'])
    table.add_row("", "Image Base", headers['optional_header']['image_base'])
    table.add_row("", "Subsystem", headers['optional_header']['subsystem'])
    
    console.print(table)
    console.print()


def display_security(analyzer: PEAnalyzer):
    """Display security features analysis."""
    security = analyzer.check_security()
    
    table = Table(
        title="[bold cyan]SECURITY FEATURES[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        padding=(0, 1)
    )
    
    table.add_column("Feature", style="bold yellow", width=25)
    table.add_column("Status", style="white", width=15, justify="center")
    table.add_column("Description", style="dim", width=45)
    
    descriptions = {
        'ASLR': 'Address Space Layout Randomization',
        'DEP/NX': 'Data Execution Prevention',
        'SafeSEH': 'Safe Structured Exception Handling',
        'CFG': 'Control Flow Guard',
        'High_Entropy_VA': 'High Entropy Virtual Address Space'
    }
    
    for feature, enabled in security.items():
        if feature == 'security_score':
            continue
        
        status = "[bold green]✓ ENABLED[/bold green]" if enabled else "[bold red]✗ DISABLED[/bold red]"
        description = descriptions.get(feature, "")
        table.add_row(feature, status, description)
    
    # Add security score
    table.add_row(
        "[bold cyan]Security Score[/bold cyan]",
        f"[bold yellow]{security['security_score']}[/bold yellow]",
        "Features enabled / Total features"
    )
    
    console.print(table)
    console.print()


def display_entropy(analyzer: PEAnalyzer):
    """Display section entropy analysis."""
    sections = analyzer.calculate_entropy()
    
    table = Table(
        title="[bold cyan]SECTION ENTROPY ANALYSIS[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        padding=(0, 1)
    )
    
    table.add_column("Section", style="bold yellow", width=15)
    table.add_column("Virtual Address", style="white", width=15)
    table.add_column("Size", style="white", width=12, justify="right")
    table.add_column("Entropy", style="bold cyan", width=10, justify="center")
    table.add_column("Risk", style="white", width=15, justify="center")
    table.add_column("Assessment", style="white", width=25)
    
    for section in sections:
        # Color code risk level
        if section['risk'] == 'CRITICAL':
            risk = f"[bold red]{section['risk']}[/bold red]"
        elif section['risk'] == 'WARNING':
            risk = f"[bold yellow]{section['risk']}[/bold yellow]"
        else:
            risk = f"[bold green]{section['risk']}[/bold green]"
        
        table.add_row(
            section['name'],
            section['virtual_address'],
            f"{section['raw_size']:,}",
            str(section['entropy']),
            risk,
            section['suspicion']
        )
    
    console.print(table)
    console.print()


def display_imports(analyzer: PEAnalyzer, max_functions: int = 10):
    """Display imported DLLs and functions."""
    imports = analyzer.get_imports()
    
    if not imports:
        console.print("[yellow]No imports found[/yellow]\n")
        return
    
    table = Table(
        title="[bold cyan]IMPORTED DLLs & FUNCTIONS[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        padding=(0, 1)
    )
    
    table.add_column("DLL", style="bold magenta", width=30)
    table.add_column("Function Count", style="yellow", width=15, justify="center")
    table.add_column("Sample Functions", style="white", width=50)
    
    for dll_import in imports[:15]:  # Limit to first 15 DLLs
        dll_name = dll_import['dll']
        func_count = len(dll_import['functions'])
        
        # Get sample functions (first few)
        sample_funcs = [f['name'] for f in dll_import['functions'][:max_functions]]
        if func_count > max_functions:
            sample_funcs.append(f"... +{func_count - max_functions} more")
        
        functions_str = "\n".join(sample_funcs)
        
        table.add_row(dll_name, str(func_count), functions_str)
    
    if len(imports) > 15:
        console.print(f"[dim]Showing 15 of {len(imports)} imported DLLs[/dim]")
    
    console.print(table)
    console.print()


def display_disassembly(disasm: Disassembler):
    """Display entry point disassembly."""
    try:
        # Get entry point info
        ep_info = disasm.get_entry_point_info()
        
        # Disassemble entry point
        instructions = disasm.disassemble_entry_point(64)
        
        if not instructions:
            console.print("[yellow]No instructions disassembled[/yellow]\n")
            return
        
        # Entry point info
        info_table = Table(
            title="[bold cyan]ENTRY POINT INFORMATION[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=False,
            padding=(0, 1)
        )
        
        info_table.add_column("Property", style="bold yellow", width=20)
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Architecture", ep_info['architecture'])
        info_table.add_row("RVA", ep_info['rva'])
        info_table.add_row("Virtual Address", ep_info['virtual_address'])
        info_table.add_row("File Offset", ep_info['file_offset'])
        info_table.add_row("Section", ep_info['section'])
        
        console.print(info_table)
        console.print()
        
        # Disassembly table
        disasm_table = Table(
            title="[bold cyan]DISASSEMBLY (First 64 bytes)[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            padding=(0, 1)
        )
        
        disasm_table.add_column("Address", style="bold yellow", width=18)
        disasm_table.add_column("Bytes", style="dim", width=25)
        disasm_table.add_column("Instruction", style="bold green", width=50)
        
        for instr in instructions[:20]:  # Show first 20 instructions
            instruction = f"{instr['mnemonic']} {instr['operands']}"
            disasm_table.add_row(
                instr['address'],
                instr['bytes'],
                instruction
            )
        
        if len(instructions) > 20:
            console.print(f"[dim]Showing 20 of {len(instructions)} instructions[/dim]")
        
        console.print(disasm_table)
        console.print()
        
    except Exception as e:
        logger.error(f"Disassembly error: {str(e)}")
        console.print(f"[bold red]❌ Disassembly failed: {str(e)}[/bold red]\n")


def run():
    """Main entry point for the Reverse Engineering module."""
    try:
        display_module_header()
        
        # Get target file
        target_file = get_target_file()
        if target_file is None:
            return
        
        console.print(f"\n[bold green]✓ Analyzing:[/bold green] {target_file.name}\n")
        logger.info(f"Starting analysis of: {target_file}")
        
        try:
            # Initialize analyzers
            with PEAnalyzer(str(target_file)) as analyzer:
                # Display analyses
                display_file_info(analyzer)
                display_headers(analyzer)
                display_security(analyzer)
                display_entropy(analyzer)
                display_imports(analyzer)
            
            # Disassembly
            with Disassembler(str(target_file)) as disasm:
                display_disassembly(disasm)
            
            # Success message
            console.print(Panel(
                "[bold green]✓ Analysis Complete[/bold green]\n"
                "All forensic data has been extracted and analyzed.",
                title="[bold cyan]═══ ANALYSIS REPORT ═══[/bold cyan]",
                border_style="green",
                box=box.DOUBLE,
                padding=(1, 2)
            ))
            
            logger.info("Analysis completed successfully")
        
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}", exc_info=True)
            console.print(f"\n[bold red]❌ Analysis Error:[/bold red] {str(e)}\n")
            console.print("[dim]This may not be a valid PE file or the file may be corrupted.[/dim]\n")
    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Analysis interrupted by user[/yellow]\n")
        logger.info("Analysis interrupted by user")
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        console.print(f"\n[bold red]❌ Unexpected Error:[/bold red] {str(e)}\n")
    
    finally:
        # Pause before returning to main menu
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
