#!/usr/bin/env python3
"""
MalSpectra - Unified Cybersecurity Framework
Main Entry Point

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
License: MIT
"""

import sys
import os
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich import box

from core.config import config
from core.logger import setup_logger


# Initialize console and logger
console = Console()
logger = setup_logger()


def display_banner() -> None:
    """Display the MalSpectra ASCII banner with cyberpunk styling."""
    banner = """
    ███╗   ███╗ █████╗ ██╗     ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ 
    ████╗ ████║██╔══██╗██║     ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
    ██╔████╔██║███████║██║     ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║
    ██║╚██╔╝██║██╔══██║██║     ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
    ██║ ╚═╝ ██║██║  ██║███████╗███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
    """
    
    # Create styled banner
    banner_text = Text(banner, style="bold cyan")
    
    # Create info panel
    info_text = Text()
    info_text.append("⚡ Advanced Unified Cybersecurity Framework ⚡\n", style="bold yellow")
    info_text.append(f"\nVersion: ", style="white")
    info_text.append(f"{config.VERSION}", style="bold green")
    info_text.append(f"\nDeveloper: ", style="white")
    info_text.append(f"{config.DEVELOPER}", style="bold magenta")
    info_text.append(f"\nEmail: ", style="white")
    info_text.append(f"{config.EMAIL}", style="italic cyan")
    info_text.append(f"\nLicense: ", style="white")
    info_text.append(f"{config.LICENSE}", style="bold blue")
    
    # Display banner
    console.print("\n")
    console.print(banner_text, justify="center")
    console.print(Panel(
        info_text,
        title="[bold red]═══ SYSTEM INFORMATION ═══[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(1, 2)
    ))
    console.print("\n")
    
    logger.info("MalSpectra framework initialized")


def display_main_menu() -> None:
    """Display the main menu with all available modules."""
    # Create table for modules
    table = Table(
        title="[bold cyan]═══ AVAILABLE MODULES ═══[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        padding=(0, 1)
    )
    
    table.add_column("#", style="bold yellow", justify="center", width=5)
    table.add_column("Module Name", style="bold green", width=30)
    table.add_column("Status", style="cyan", justify="center", width=15)
    
    # Add modules to table
    for idx, module in enumerate(config.MODULES, 1):
        table.add_row(
            str(idx),
            f"🔒 {module}",
            "[yellow]Development[/yellow]"
        )
    
    # Add exit option
    table.add_row(
        "0",
        "❌ Exit MalSpectra",
        "[red]System[/red]"
    )
    
    console.print(table)
    console.print()


def execute_module(module_name: str) -> None:
    """
    Execute the selected module.
    
    Args:
        module_name: Name of the module to execute
    """
    logger.info(f"Module selected: {module_name}")
    
    # Module under construction message
    message = Text()
    message.append("⚠️  Module Status: ", style="bold yellow")
    message.append("UNDER CONSTRUCTION", style="bold red blink")
    message.append("\n\nThis module is currently being developed.", style="white")
    message.append(f"\n\nModule: ", style="white")
    message.append(f"{module_name}", style="bold cyan")
    message.append("\n\nStay tuned for updates! 🚀", style="italic green")
    
    console.print()
    console.print(Panel(
        message,
        title=f"[bold red]═══ {module_name.upper()} ═══[/bold red]",
        border_style="yellow",
        box=box.HEAVY,
        padding=(1, 2)
    ))
    console.print()
    
    logger.warning(f"Module '{module_name}' is under construction")
    
    # Pause before returning to menu
    console.print("[dim]Press Enter to return to main menu...[/dim]", style="italic")
    input()


def main_loop() -> None:
    """Main application loop."""
    logger.info("Entering main application loop")
    
    while True:
        try:
            # Clear screen for clean display
            os.system('clear' if os.name != 'nt' else 'cls')
            
            # Display menu
            display_main_menu()
            
            # Get user choice
            choice = Prompt.ask(
                "[bold cyan]Select a module[/bold cyan]",
                default="0"
            )
            
            # Validate and process choice
            try:
                choice_num = int(choice)
                
                if choice_num == 0:
                    # Exit application
                    logger.info("User initiated exit")
                    console.print()
                    console.print(Panel(
                        "[bold green]Thank you for using MalSpectra!\n"
                        "Stay secure! 🛡️[/bold green]",
                        title="[bold red]═══ GOODBYE ═══[/bold red]",
                        border_style="red",
                        box=box.DOUBLE,
                        padding=(1, 2)
                    ))
                    console.print()
                    logger.info("MalSpectra shutting down")
                    sys.exit(0)
                
                elif 1 <= choice_num <= len(config.MODULES):
                    # Execute selected module
                    module_name = config.MODULES[choice_num - 1]
                    execute_module(module_name)
                
                else:
                    logger.warning(f"Invalid choice: {choice_num}")
                    console.print(
                        f"\n[bold red]❌ Invalid choice: {choice_num}[/bold red]",
                        style="bold"
                    )
                    console.print("[dim]Please select a valid option (0-12)[/dim]")
                    console.print()
                    input("Press Enter to continue...")
            
            except ValueError:
                logger.warning(f"Invalid input: {choice}")
                console.print(
                    f"\n[bold red]❌ Invalid input: '{choice}'[/bold red]",
                    style="bold"
                )
                console.print("[dim]Please enter a number (0-12)[/dim]")
                console.print()
                input("Press Enter to continue...")
        
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            logger.info("Keyboard interrupt received")
            console.print("\n\n[bold yellow]⚠️  Interrupt detected[/bold yellow]")
            console.print("[dim]Use option 0 to exit properly[/dim]")
            console.print()
            input("Press Enter to continue...")
        
        except Exception as e:
            # Log unexpected errors
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            console.print(
                f"\n[bold red]❌ Error: {str(e)}[/bold red]",
                style="bold"
            )
            console.print()
            input("Press Enter to continue...")


def main() -> None:
    """Main entry point of the application."""
    try:
        # Display banner and welcome message
        display_banner()
        
        # Start main application loop
        main_loop()
    
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        console.print(
            f"\n[bold red]💀 FATAL ERROR: {str(e)}[/bold red]",
            style="bold"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
