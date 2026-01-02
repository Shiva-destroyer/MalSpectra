"""
MalSpectra - Code Injection Framework Module
Main entry point for ptrace-based process injection

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from pathlib import Path

from .injector import ProcessInjector
from .payloads import Payloads


console = Console()


def display_module_banner():
    """Display module banner with safety warning."""
    banner_text = """
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
[bold green]          CODE INJECTION FRAMEWORK (PTRACE)[/bold green]
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]

[yellow]Linux process injection using ptrace system call[/yellow]
[dim]Injects shellcode into running processes[/dim]
"""
    console.print(banner_text)


def display_safety_warning():
    """Display safety warning."""
    warning_text = """
[bold red]⚠️  CRITICAL WARNING ⚠️[/bold red]

[bold yellow]This module requires ROOT privileges![/bold yellow]

[bold red]RISKS:[/bold red]
• Process corruption
• System instability
• Security implications
• Potential data loss

[bold green]USE ONLY:[/bold green]
• For educational purposes
• In isolated test environments
• With test processes you own
• With harmless payloads

[bold yellow]DO NOT:[/bold yellow]
• Inject into system processes
• Use on production systems
• Inject malicious code
• Use without understanding consequences
"""
    
    panel = Panel(
        warning_text,
        title="[bold red]DANGER[/bold red]",
        border_style="bold red",
        expand=False
    )
    
    console.print("\n")
    console.print(panel)
    console.print("\n")


def check_root() -> bool:
    """
    Check if running as root.
    
    Returns:
        True if root, False otherwise
    """
    return os.geteuid() == 0


def get_user_confirmation() -> bool:
    """
    Get user confirmation.
    
    Returns:
        True if confirmed, False otherwise
    """
    console.print("[bold yellow]Do you understand the risks and have proper authorization?[/bold yellow]")
    response = console.input("[bold cyan]Type 'YES' to confirm: [/bold cyan]")
    
    return response.strip().upper() == 'YES'


def list_processes() -> list:
    """
    Get list of user processes.
    
    Returns:
        List of (pid, name, username) tuples
    """
    processes = []
    current_user = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            info = proc.info
            # Only show processes from current user (safer)
            if info['username'] == current_user:
                processes.append((
                    info['pid'],
                    info['name'],
                    info['username']
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return sorted(processes, key=lambda x: x[0])


def display_processes(processes: list):
    """
    Display available processes.
    
    Args:
        processes: List of process tuples
    """
    console.print("\n[bold yellow]═══ YOUR PROCESSES ═══[/bold yellow]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="cyan", width=5)
    table.add_column("PID", style="green", width=10)
    table.add_column("Process Name", style="yellow", width=30)
    table.add_column("User", style="blue", width=15)
    
    for i, (pid, name, username) in enumerate(processes[:50], 1):  # Limit to 50
        table.add_row(str(i), str(pid), name, username)
    
    console.print(table)
    
    if len(processes) > 50:
        console.print(f"\n[dim]...and {len(processes) - 50} more processes[/dim]")


def select_process(processes: list) -> int:
    """
    Prompt user to select a process.
    
    Args:
        processes: List of process tuples
        
    Returns:
        Selected PID or None
    """
    while True:
        console.print("\n[bold cyan]Select process number (or 'q' to quit):[/bold cyan]")
        choice = console.input("[cyan]> [/cyan]").strip()
        
        if choice.lower() == 'q':
            return None
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < min(len(processes), 50):
                return processes[idx][0]  # Return PID
            else:
                console.print(f"[red]Invalid choice. Please select 1-{min(len(processes), 50)}[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number[/red]")


def display_payloads():
    """Display available payloads."""
    console.print("\n[bold yellow]═══ AVAILABLE PAYLOADS ═══[/bold yellow]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="cyan", width=5)
    table.add_column("Name", style="green", width=20)
    table.add_column("Description", style="yellow", width=35)
    table.add_column("Size", style="blue", width=10)
    
    payloads = Payloads.get_available_payloads()
    
    for i, name in enumerate(payloads, 1):
        payload = Payloads.get_payload(name)
        table.add_row(
            str(i),
            payload['name'],
            payload['description'],
            f"{len(payload['bytes'])} bytes"
        )
    
    console.print(table)


def select_payload() -> str:
    """
    Prompt user to select a payload.
    
    Returns:
        Payload name or None
    """
    payloads = Payloads.get_available_payloads()
    
    while True:
        console.print("\n[bold cyan]Select payload number (or 'q' to quit):[/bold cyan]")
        choice = console.input("[cyan]> [/cyan]").strip()
        
        if choice.lower() == 'q':
            return None
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(payloads):
                return payloads[idx]
            else:
                console.print(f"[red]Invalid choice. Please select 1-{len(payloads)}[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number[/red]")


def run():
    """Main entry point for code injection module."""
    
    # Display banner
    display_module_banner()
    
    # Display safety warning
    display_safety_warning()
    
    # Check root
    if not check_root():
        console.print("\n[bold red]Error: Root privileges required[/bold red]")
        console.print("[yellow]This module requires root to use ptrace[/yellow]")
        console.print("\n[cyan]Run with: sudo python3 main.py[/cyan]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    console.print("[bold green]✓ Running as root[/bold green]")
    
    # Get user confirmation
    if not get_user_confirmation():
        console.print("\n[bold red]Operation aborted. Stay safe![/bold red]\n")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    console.print("\n[bold green]✓ Authorization confirmed[/bold green]")
    
    # List processes
    console.print("\n[bold cyan]Scanning for your processes...[/bold cyan]")
    processes = list_processes()
    
    if not processes:
        console.print("\n[bold red]No processes found[/bold red]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    # Display processes
    display_processes(processes)
    
    # Select process
    selected_pid = select_process(processes)
    
    if not selected_pid:
        console.print("\n[yellow]Operation cancelled[/yellow]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    console.print(f"\n[bold green]✓ Selected PID:[/bold green] {selected_pid}")
    
    # Display payloads
    display_payloads()
    
    # Select payload
    payload_name = select_payload()
    
    if not payload_name:
        console.print("\n[yellow]Operation cancelled[/yellow]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    payload_info = Payloads.get_payload(payload_name)
    shellcode = payload_info['bytes']
    
    console.print(f"\n[bold green]✓ Selected payload:[/bold green] {payload_info['name']}")
    console.print(f"[dim]{payload_info['description']}[/dim]")
    console.print(f"[dim]Size: {len(shellcode)} bytes[/dim]")
    console.print(f"[dim]Hex: {shellcode.hex()}[/dim]")
    
    # Final confirmation
    console.print("\n[bold yellow]⚠️  Ready to inject shellcode into process![/bold yellow]")
    console.print(f"[yellow]Target PID: {selected_pid}[/yellow]")
    console.print(f"[yellow]Payload: {payload_info['name']}[/yellow]")
    
    confirm = Prompt.ask("\n[bold cyan]Proceed with injection?[/bold cyan]", choices=["y", "n"], default="n")
    
    if confirm.lower() != 'y':
        console.print("\n[yellow]Injection cancelled[/yellow]")
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()
        return
    
    # Perform injection
    console.print("\n[bold cyan]Injecting shellcode...[/bold cyan]")
    
    try:
        injector = ProcessInjector()
        
        console.print(f"[dim]Attaching to PID {selected_pid}...[/dim]")
        
        success = injector.inject_shellcode(selected_pid, shellcode)
        
        if success:
            console.print("\n[bold green]✓ Injection successful![/bold green]")
            console.print(f"[green]Shellcode injected into process {selected_pid}[/green]")
            
            result_panel = Panel(
                f"[bold green]Injection Complete[/bold green]\n\n"
                f"[yellow]Target PID:[/yellow] {selected_pid}\n"
                f"[yellow]Payload:[/yellow] {payload_info['name']}\n"
                f"[yellow]Size:[/yellow] {len(shellcode)} bytes\n"
                f"[yellow]Status:[/yellow] Success\n\n"
                f"[dim]The process may crash or behave unexpectedly[/dim]",
                title="[bold green]Result[/bold green]",
                border_style="green"
            )
            console.print("\n")
            console.print(result_panel)
        else:
            console.print("\n[bold red]✗ Injection failed[/bold red]")
            console.print("[yellow]Common issues:[/yellow]")
            console.print("  - Process terminated during injection")
            console.print("  - Insufficient permissions")
            console.print("  - Process protected by security policy")
    
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        console.print("[dim]Check logs for details[/dim]")
    
    # Pause
    console.print("\n[dim]Press Enter to return to main menu...[/dim]")
    input()


if __name__ == "__main__":
    run()
