"""
MalSpectra - Dynamic Sandbox Module
Main entry point for sandbox execution

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pathlib import Path

from .sandbox import Sandbox, SandboxReport


console = Console()


def display_safety_warning():
    """Display BRIGHT RED safety warning."""
    warning_text = """
[bold red]⚠️  CRITICAL SAFETY WARNING ⚠️[/bold red]

[bold yellow]THIS MODULE EXECUTES POTENTIALLY MALICIOUS CODE![/bold yellow]

[bold red]DO NOT RUN THIS ON YOUR HOST MACHINE![/bold red]

[bold green]Requirements:[/bold green]
• Run ONLY inside a Virtual Machine (VM)
• Ensure VM has NO network access to production systems
• Take VM snapshot before testing
• Use disposable VMs that can be reset

[bold yellow]Failure to follow these guidelines may result in:[/bold yellow]
• System compromise
• Data loss
• Network infection
• Irreversible damage

[bold cyan]Press Ctrl+C to abort if you are NOT in a safe VM environment.[/bold cyan]
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


def get_user_confirmation() -> bool:
    """
    Get user confirmation that they're in a VM.
    
    Returns:
        True if user confirms, False otherwise
    """
    console.print("[bold yellow]Are you running inside a Virtual Machine?[/bold yellow]")
    response = console.input("[bold cyan]Type 'YES' to confirm: [/bold cyan]")
    
    return response.strip().upper() == 'YES'


def get_target_file() -> str:
    """
    Prompt user for target file to execute.
    
    Returns:
        Path to target file
    """
    while True:
        console.print("\n[bold cyan]Enter path to file to execute in sandbox:[/bold cyan]")
        file_path = console.input("[cyan]> [/cyan]").strip()
        
        if not file_path:
            console.print("[red]Error: No file path provided[/red]")
            continue
        
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            continue
        
        return file_path


def get_timeout() -> int:
    """
    Prompt user for execution timeout.
    
    Returns:
        Timeout in seconds
    """
    console.print("\n[bold cyan]Enter execution timeout (seconds):[/bold cyan]")
    console.print("[dim](Default: 10 seconds)[/dim]")
    
    timeout_input = console.input("[cyan]> [/cyan]").strip()
    
    if not timeout_input:
        return 10
    
    try:
        timeout = int(timeout_input)
        if timeout < 1:
            console.print("[yellow]Warning: Using minimum timeout of 1 second[/yellow]")
            return 1
        if timeout > 300:
            console.print("[yellow]Warning: Using maximum timeout of 300 seconds[/yellow]")
            return 300
        return timeout
    except ValueError:
        console.print("[yellow]Invalid input, using default 10 seconds[/yellow]")
        return 10


def display_report(report: SandboxReport):
    """
    Display sandbox execution report.
    
    Args:
        report: Sandbox report to display
    """
    console.print("\n")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print("[bold green]       SANDBOX EXECUTION REPORT        [/bold green]")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    
    # Execution Summary
    summary_table = Table(title="Execution Summary", show_header=True, header_style="bold magenta")
    summary_table.add_column("Property", style="cyan")
    summary_table.add_column("Value", style="yellow")
    
    summary_table.add_row("Target File", report.target_file)
    summary_table.add_row("Execution Time", f"{report.execution_time:.2f}s")
    summary_table.add_row("Exit Code", str(report.exit_code) if report.exit_code is not None else "N/A")
    summary_table.add_row("Timed Out", "Yes" if report.timed_out else "No")
    
    if report.error_message:
        summary_table.add_row("Error", f"[red]{report.error_message}[/red]")
    
    console.print(summary_table)
    
    # Process Activity
    if report.new_processes:
        console.print("\n[bold yellow]New Processes Created:[/bold yellow]")
        proc_table = Table(show_header=True, header_style="bold magenta")
        proc_table.add_column("PID", style="cyan")
        proc_table.add_column("Name", style="yellow")
        proc_table.add_column("User", style="green")
        
        for proc in report.new_processes[:10]:  # Show first 10
            proc_table.add_row(
                str(proc.pid),
                proc.name,
                proc.username
            )
        
        console.print(proc_table)
        
        if len(report.new_processes) > 10:
            console.print(f"[dim]...and {len(report.new_processes) - 10} more processes[/dim]")
    else:
        console.print("\n[dim]No new processes detected[/dim]")
    
    # File Changes
    if report.file_changes:
        console.print("\n[bold yellow]File System Changes:[/bold yellow]")
        file_table = Table(show_header=True, header_style="bold magenta")
        file_table.add_column("Type", style="cyan")
        file_table.add_column("Path", style="yellow")
        file_table.add_column("Size", style="green")
        
        for change in report.file_changes[:15]:  # Show first 15
            color = "green" if change.change_type == "created" else "yellow" if change.change_type == "modified" else "red"
            file_table.add_row(
                f"[{color}]{change.change_type.upper()}[/{color}]",
                change.path,
                f"{change.size} bytes" if change.size > 0 else "-"
            )
        
        console.print(file_table)
        
        if len(report.file_changes) > 15:
            console.print(f"[dim]...and {len(report.file_changes) - 15} more changes[/dim]")
    else:
        console.print("\n[dim]No file changes detected[/dim]")
    
    # Network Activity
    if report.network_connections:
        console.print("\n[bold yellow]Network Connections:[/bold yellow]")
        net_table = Table(show_header=True, header_style="bold magenta")
        net_table.add_column("Process", style="cyan")
        net_table.add_column("Local", style="yellow")
        net_table.add_column("Remote", style="red")
        net_table.add_column("Status", style="green")
        
        for conn in report.network_connections[:10]:  # Show first 10
            net_table.add_row(
                f"{conn.process_name} ({conn.pid})",
                f"{conn.local_address}:{conn.local_port}",
                f"{conn.remote_address}:{conn.remote_port}",
                conn.status
            )
        
        console.print(net_table)
        
        if len(report.network_connections) > 10:
            console.print(f"[dim]...and {len(report.network_connections) - 10} more connections[/dim]")
    else:
        console.print("\n[dim]No new network connections detected[/dim]")
    
    console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]\n")


def run():
    """Main entry point for sandbox module."""
    
    # Display safety warning
    display_safety_warning()
    
    # Get user confirmation
    if not get_user_confirmation():
        console.print("\n[bold red]Sandbox execution aborted. Stay safe![/bold red]\n")
        return
    
    console.print("\n[bold green]✓ VM confirmation received[/bold green]")
    
    # Get target file
    target_file = get_target_file()
    
    # Get timeout
    timeout = get_timeout()
    
    # Confirm execution
    console.print(f"\n[bold yellow]Ready to execute:[/bold yellow]")
    console.print(f"  File: [cyan]{target_file}[/cyan]")
    console.print(f"  Timeout: [cyan]{timeout}s[/cyan]")
    console.print("\n[bold yellow]Press Enter to continue or Ctrl+C to abort...[/bold yellow]")
    console.input()
    
    # Execute in sandbox
    console.print("\n[bold green]Executing in sandbox...[/bold green]")
    console.print("[dim]Monitoring: processes, files, network[/dim]\n")
    
    sandbox = Sandbox()
    report = sandbox.execute(target_file, timeout=timeout)
    
    # Display results
    display_report(report)


if __name__ == "__main__":
    run()
