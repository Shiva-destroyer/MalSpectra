"""
MalSpectra - Behavioral Signature Generator Module
Main entry point for YARA rule generation

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from pathlib import Path

from .yara_builder import YaraBuilder


console = Console()


def display_module_banner():
    """Display module banner."""
    banner_text = """
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
[bold green]         BEHAVIORAL SIGNATURE GENERATOR (YARA)[/bold green]
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]

[yellow]Automatically generates YARA rules from binary files[/yellow]
[dim]Extracts: Strings, Opcodes, and Metadata[/dim]
"""
    console.print(banner_text)


def get_target_file() -> str:
    """
    Prompt user for target file.
    
    Returns:
        Path to target file
    """
    while True:
        console.print("\n[bold cyan]Enter path to binary file:[/bold cyan]")
        file_path = console.input("[cyan]> [/cyan]").strip()
        
        if not file_path:
            console.print("[red]Error: No file path provided[/red]")
            continue
        
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            continue
        
        if not path.is_file():
            console.print(f"[red]Error: Not a file: {file_path}[/red]")
            continue
        
        return file_path


def get_rule_name() -> str:
    """
    Prompt user for rule name (optional).
    
    Returns:
        Rule name or empty string
    """
    console.print("\n[bold cyan]Enter YARA rule name (optional, press Enter for auto):[/bold cyan]")
    rule_name = console.input("[cyan]> [/cyan]").strip()
    
    # Validate rule name
    if rule_name:
        # Remove invalid characters
        rule_name = ''.join(c for c in rule_name if c.isalnum() or c == '_')
        if rule_name and not rule_name[0].isalpha():
            rule_name = 'rule_' + rule_name
    
    return rule_name


def display_extracted_data(builder: YaraBuilder):
    """
    Display extracted strings and opcodes.
    
    Args:
        builder: YaraBuilder instance
    """
    console.print("\n[bold yellow]═══ EXTRACTED DATA ═══[/bold yellow]")
    
    # Display strings
    if builder.strings:
        console.print(f"\n[bold green]Strings Found:[/bold green] {len(builder.strings)}")
        
        string_table = Table(show_header=True, header_style="bold magenta")
        string_table.add_column("#", style="cyan", width=5)
        string_table.add_column("String", style="yellow")
        string_table.add_column("Length", style="green", justify="right")
        
        for i, s in enumerate(builder.strings[:15], 1):  # Show first 15
            display_str = s if len(s) <= 60 else s[:57] + "..."
            string_table.add_row(str(i), display_str, str(len(s)))
        
        console.print(string_table)
        
        if len(builder.strings) > 15:
            console.print(f"[dim]...and {len(builder.strings) - 15} more strings[/dim]")
    else:
        console.print("\n[dim]No strings extracted[/dim]")
    
    # Display opcodes
    if builder.opcodes:
        console.print(f"\n[bold green]Opcodes (Entry Point):[/bold green]")
        console.print(f"[cyan]{builder.opcodes}[/cyan]")
    else:
        console.print("\n[dim]No opcodes extracted[/dim]")


def display_yara_rule(rule_content: str):
    """
    Display YARA rule with syntax highlighting.
    
    Args:
        rule_content: YARA rule content
    """
    console.print("\n[bold yellow]═══ GENERATED YARA RULE ═══[/bold yellow]\n")
    
    # Use syntax highlighting for YARA rules
    # Rich doesn't have built-in YARA syntax, use 'c' as close approximation
    syntax = Syntax(rule_content, "c", theme="monokai", line_numbers=True)
    console.print(syntax)


def save_rule_to_file(builder: YaraBuilder, output_dir: str = "./data"):
    """
    Save YARA rule to file.
    
    Args:
        builder: YaraBuilder instance
        output_dir: Output directory
        
    Returns:
        Path to saved file
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create filename
    output_file = output_path / "detected.yar"
    
    # Save rule
    builder.save_rule(str(output_file))
    
    return output_file


def run():
    """Main entry point for signature generator module."""
    
    # Display banner
    display_module_banner()
    
    # Get target file
    target_file = get_target_file()
    
    console.print(f"\n[bold green]✓ Target file:[/bold green] {target_file}")
    
    # Get rule name (optional)
    rule_name = get_rule_name()
    
    if rule_name:
        console.print(f"[bold green]✓ Rule name:[/bold green] {rule_name}")
    else:
        console.print("[dim]Using auto-generated rule name[/dim]")
    
    # Build YARA rule
    console.print("\n[bold cyan]Analyzing binary...[/bold cyan]")
    
    try:
        # Create builder
        builder = YaraBuilder(target_file)
        
        # Extract data
        console.print("[dim]Extracting strings...[/dim]")
        builder.extract_strings()
        
        console.print("[dim]Extracting opcodes...[/dim]")
        builder.extract_opcodes()
        
        # Display extracted data
        display_extracted_data(builder)
        
        # Generate rule
        console.print("\n[bold cyan]Generating YARA rule...[/bold cyan]")
        
        if rule_name:
            rule_content = builder.build_rule(rule_name)
        else:
            rule_content = builder.build_rule()
        
        # Display rule
        display_yara_rule(rule_content)
        
        # Save to file
        console.print("\n[bold cyan]Saving rule to file...[/bold cyan]")
        output_file = save_rule_to_file(builder)
        
        console.print(f"\n[bold green]✓ YARA rule saved to:[/bold green] {output_file}")
        
        # Usage instructions
        usage_panel = Panel(
            f"[bold yellow]Usage:[/bold yellow]\n\n"
            f"[cyan]yara {output_file} /path/to/scan/[/cyan]\n\n"
            f"[dim]This will scan files against the generated rule[/dim]",
            title="[bold green]How to Use This Rule[/bold green]",
            border_style="green"
        )
        console.print("\n")
        console.print(usage_panel)
        
    except FileNotFoundError as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
    
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        console.print("[dim]Check logs for details[/dim]")
    
    # Pause
    console.print("\n[dim]Press Enter to return to main menu...[/dim]")
    input()


if __name__ == "__main__":
    run()
