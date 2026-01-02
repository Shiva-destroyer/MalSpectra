"""
MalSpectra - API Hooking Framework Module
Main entry point for LD_PRELOAD hook generation

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.prompt import Prompt
from pathlib import Path

from .hook_generator import HookGenerator


console = Console()


def display_module_banner():
    """Display module banner."""
    banner_text = """
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
[bold green]            API HOOKING FRAMEWORK (LD_PRELOAD)[/bold green]
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]

[yellow]Generate function hooks for Linux using LD_PRELOAD[/yellow]
[dim]Intercept: fopen, write, connect, socket, malloc, and more[/dim]
"""
    console.print(banner_text)


def display_available_functions(generator: HookGenerator):
    """
    Display available functions to hook.
    
    Args:
        generator: HookGenerator instance
    """
    functions = generator.get_available_functions()
    
    console.print("\n[bold yellow]═══ AVAILABLE FUNCTIONS ═══[/bold yellow]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="cyan", width=5)
    table.add_column("Function", style="green", width=20)
    table.add_column("Category", style="yellow", width=15)
    
    # Categorize functions
    categories = {
        'fopen': 'File I/O',
        'fclose': 'File I/O',
        'open': 'File I/O',
        'read': 'File I/O',
        'write': 'File I/O',
        'socket': 'Network',
        'connect': 'Network',
        'malloc': 'Memory'
    }
    
    for i, func in enumerate(functions, 1):
        category = categories.get(func, 'System')
        table.add_row(str(i), func, category)
    
    console.print(table)


def select_function(generator: HookGenerator) -> str:
    """
    Prompt user to select a function to hook.
    
    Args:
        generator: HookGenerator instance
        
    Returns:
        Selected function name
    """
    functions = generator.get_available_functions()
    
    while True:
        console.print("\n[bold cyan]Select function number to hook (or 'q' to quit):[/bold cyan]")
        choice = console.input("[cyan]> [/cyan]").strip()
        
        if choice.lower() == 'q':
            return None
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(functions):
                return functions[idx]
            else:
                console.print(f"[red]Invalid choice. Please select 1-{len(functions)}[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number[/red]")


def get_output_filename(function_name: str) -> str:
    """
    Prompt user for output filename.
    
    Args:
        function_name: Name of hooked function
        
    Returns:
        Output filename
    """
    default_name = f"{function_name}_hook.so"
    
    console.print(f"\n[bold cyan]Enter output filename (default: {default_name}):[/bold cyan]")
    filename = console.input("[cyan]> [/cyan]").strip()
    
    if not filename:
        return default_name
    
    # Ensure .so extension
    if not filename.endswith('.so'):
        filename += '.so'
    
    return filename


def display_generated_code(code: str):
    """
    Display generated C code with syntax highlighting.
    
    Args:
        code: C source code
    """
    console.print("\n[bold yellow]═══ GENERATED HOOK CODE ═══[/bold yellow]\n")
    
    syntax = Syntax(code, "c", theme="monokai", line_numbers=True)
    console.print(syntax)


def display_usage_instructions(output_file: str):
    """
    Display usage instructions for the generated hook.
    
    Args:
        output_file: Path to compiled .so file
    """
    usage_text = f"""[bold yellow]Usage Instructions:[/bold yellow]

[bold green]1. Basic Usage:[/bold green]
   [cyan]LD_PRELOAD=./{output_file} /path/to/target[/cyan]

[bold green]2. With Arguments:[/bold green]
   [cyan]LD_PRELOAD=./{output_file} /path/to/target arg1 arg2[/cyan]

[bold green]3. Python Script:[/bold green]
   [cyan]LD_PRELOAD=./{output_file} python3 script.py[/cyan]

[bold green]4. Check Output:[/bold green]
   Hooked function calls will be printed to [yellow]stderr[/yellow]
   [cyan]LD_PRELOAD=./{output_file} ./target 2> hooks.log[/cyan]

[bold green]5. Test with 'ls' command:[/bold green]
   [cyan]LD_PRELOAD=./{output_file} ls[/cyan]

[dim]Note: Hook intercepts function calls in dynamically linked executables[/dim]
"""
    
    panel = Panel(
        usage_text,
        title="[bold green]How to Use This Hook[/bold green]",
        border_style="green",
        expand=False
    )
    
    console.print("\n")
    console.print(panel)


def check_gcc_available() -> bool:
    """
    Check if gcc is available.
    
    Returns:
        True if gcc is available, False otherwise
    """
    import subprocess
    
    try:
        result = subprocess.run(
            ['gcc', '--version'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run():
    """Main entry point for API hooking module."""
    
    # Display banner
    display_module_banner()
    
    # Check for gcc
    if not check_gcc_available():
        console.print("\n[bold red]Error: gcc not found[/bold red]")
        console.print("[yellow]Please install gcc:[/yellow]")
        console.print("  [cyan]sudo apt install build-essential  # Debian/Ubuntu[/cyan]")
        console.print("  [cyan]sudo yum install gcc             # RHEL/CentOS[/cyan]")
        console.print("  [cyan]sudo pacman -S gcc               # Arch Linux[/cyan]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    # Create generator
    generator = HookGenerator()
    
    # Display available functions
    display_available_functions(generator)
    
    # Select function
    function_name = select_function(generator)
    
    if not function_name:
        console.print("\n[yellow]Operation cancelled[/yellow]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    console.print(f"\n[bold green]✓ Selected function:[/bold green] {function_name}")
    
    # Get output filename
    output_file = get_output_filename(function_name)
    console.print(f"[bold green]✓ Output file:[/bold green] {output_file}")
    
    # Generate hook code
    console.print("\n[bold cyan]Generating hook code...[/bold cyan]")
    
    code = generator.generate_hook_code(function_name)
    
    if not code:
        console.print(f"[bold red]Error:[/bold red] Failed to generate code for {function_name}")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    # Display generated code
    display_generated_code(code)
    
    # Ask for confirmation to compile
    console.print("\n[bold yellow]Compile this hook?[/bold yellow]")
    confirm = Prompt.ask("[cyan]Continue?[/cyan]", choices=["y", "n"], default="y")
    
    if confirm.lower() != 'y':
        console.print("\n[yellow]Compilation cancelled[/yellow]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    # Compile hook
    console.print("\n[bold cyan]Compiling hook...[/bold cyan]")
    console.print("[dim]Running: gcc -shared -fPIC -o hook.so hook.c -ldl[/dim]")
    
    success = generator.compile_hook(code, output_file)
    
    if success:
        console.print(f"\n[bold green]✓ Hook compiled successfully![/bold green]")
        console.print(f"[bold green]✓ Output:[/bold green] {output_file}")
        
        # Display usage instructions
        display_usage_instructions(output_file)
        
        # Save code to file for reference
        code_file = Path(output_file).with_suffix('.c')
        code_file.write_text(code)
        console.print(f"\n[dim]Source code saved to: {code_file}[/dim]")
        
    else:
        console.print(f"\n[bold red]✗ Compilation failed[/bold red]")
        console.print("[yellow]Common issues:[/yellow]")
        console.print("  - Missing build-essential package")
        console.print("  - Insufficient permissions")
        console.print("  - Invalid C code")
    
    # Pause
    console.print("\n[dim]Press Enter to return to main menu...[/dim]")
    input()


if __name__ == "__main__":
    run()
