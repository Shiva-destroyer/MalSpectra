"""
Ransomware Decryption Helper - User Interface
Interactive ransomware identification and decryption assistance

Developer: Sai Srujan Murthy
Contact: saisrujanmurthy@gmail.com
"""

import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .identifier import RansomwareIdentifier


console = Console()


def display_banner():
    """Display module banner"""
    banner = Text()
    banner.append("═══ RANSOMWARE DECRYPTION HELPER ═══\n", style="bold cyan")
    banner.append("Family Identification & Decryption Resources\n", style="dim")
    banner.append("\nDeveloper: Sai Srujan Murthy\n", style="dim")
    banner.append("Email: saisrujanmurthy@gmail.com", style="dim")
    
    console.print(Panel(banner, border_style="cyan"))
    console.print()


def display_warning():
    """Display important warning"""
    warning = Panel(
        "[bold yellow]⚠ IMPORTANT NOTES ⚠[/bold yellow]\n\n"
        "• This tool identifies ransomware families\n"
        "• It does NOT decrypt files directly\n"
        "• Provides links to legitimate decryption tools\n"
        "• Always backup encrypted files before attempting decryption\n"
        "• Some ransomware families have no decryption available\n"
        "• Never pay the ransom - it encourages criminals",
        border_style="yellow",
        padding=(1, 2)
    )
    console.print(warning)
    console.print()


def get_target_file() -> str:
    """Get encrypted file from user"""
    console.print("[bold cyan]Select Encrypted File[/bold cyan]\n")
    
    # Look for suspicious files in data directory
    data_dir = Path("data")
    if data_dir.exists():
        suspicious_files = []
        for pattern in ['*.locked', '*.encrypted', '*.locky', '*.wannacry', '*.cerber', '*.crypto']:
            suspicious_files.extend(list(data_dir.glob(pattern)))
        
        if suspicious_files:
            console.print("[dim]Suspicious files found in data/:[/dim]\n")
            for i, file in enumerate(suspicious_files, 1):
                size_kb = file.stat().st_size / 1024
                console.print(f"  [{i}] {file.name} ({size_kb:.2f} KB)")
            console.print()
    
    # Get file path
    file_path = console.input("[cyan]Enter encrypted file path:[/cyan] ").strip()
    
    if not file_path:
        return None
    
    # Handle relative paths
    path = Path(file_path)
    if not path.is_absolute():
        path = Path("data") / path
    
    if not path.exists():
        console.print(f"[red]✗[/red] File not found: {path}\n")
        return None
    
    return str(path)


def display_file_info(info):
    """Display file information"""
    console.print("\n[bold cyan]File Information:[/bold cyan]\n")
    
    table = Table(show_header=False, border_style="cyan")
    table.add_column("Property", style="dim")
    table.add_column("Value", style="white")
    
    table.add_row("File Name", info['name'])
    table.add_row("File Size", info['size_formatted'])
    table.add_row("Extension", info['extension'] or '(none)')
    table.add_row("Full Path", info['path'])
    
    console.print(table)
    console.print()


def display_family_identification(family_info):
    """Display ransomware family identification"""
    console.print("[bold cyan]Ransomware Family Identification:[/bold cyan]\n")
    
    if family_info is None:
        console.print("[yellow]⚠ UNKNOWN[/yellow] - Could not identify ransomware family\n")
        console.print("[dim]This could mean:[/dim]")
        console.print("  • Unknown or new ransomware variant")
        console.print("  • Custom or targeted ransomware")
        console.print("  • File is not actually encrypted by ransomware")
        console.print("  • Extension was manually changed\n")
        return False
    
    # Confidence indicator
    confidence = family_info.get('confidence', 'UNKNOWN')
    if confidence == 'HIGH':
        conf_style = "green"
        conf_icon = "✓"
    elif confidence == 'MEDIUM':
        conf_style = "yellow"
        conf_icon = "⚠"
    else:
        conf_style = "red"
        conf_icon = "?"
    
    console.print(f"[{conf_style}]{conf_icon} IDENTIFIED[/{conf_style}] - Confidence: {confidence}\n")
    
    # Family details table
    table = Table(title=f"Ransomware Family: {family_info['family']}", border_style="red")
    table.add_column("Attribute", style="cyan")
    table.add_column("Details", style="white")
    
    table.add_row("Family Name", family_info['family'])
    table.add_row("Extension", family_info['extension'])
    table.add_row("Also Known As", ", ".join(family_info.get('aka', [])))
    table.add_row("First Seen", family_info.get('year', 'Unknown'))
    table.add_row("Severity", f"[red]{family_info.get('severity', 'UNKNOWN')}[/red]")
    table.add_row("Description", family_info.get('description', 'No description available'))
    
    if family_info.get('decryptor_available'):
        table.add_row("Decryptor", "[green]✓ Available[/green]")
    
    console.print(table)
    console.print()
    
    if family_info.get('note'):
        console.print(f"[dim]Note: {family_info['note']}[/dim]\n")
    
    return True


def display_encryption_verification(verification):
    """Display encryption verification results"""
    console.print("[bold cyan]Encryption Verification:[/bold cyan]\n")
    
    entropy = verification['entropy']
    is_encrypted = verification['is_encrypted']
    assessment = verification['assessment']
    
    # Display entropy bar
    console.print(f"Shannon Entropy: [bold]{entropy:.4f}[/bold] / 8.0000")
    
    # Visual bar
    bar_length = int((entropy / 8.0) * 40)
    bar = "█" * bar_length + "░" * (40 - bar_length)
    
    if entropy >= 7.5:
        bar_color = "red"
    elif entropy >= 7.0:
        bar_color = "yellow"
    else:
        bar_color = "green"
    
    console.print(f"[{bar_color}]{bar}[/{bar_color}]")
    console.print(f"Threshold: {verification['threshold']}\n")
    
    # Assessment
    if is_encrypted:
        console.print(f"[red]✗ ENCRYPTED[/red] - {assessment}\n")
    else:
        console.print(f"[green]✓ NOT ENCRYPTED[/green] - {assessment}\n")


def display_recommendations(results):
    """Display recommendations based on analysis"""
    action = results['recommended_action']
    family_info = results['family_identification']
    
    console.print("═" * 70)
    console.print()
    console.print("[bold cyan]Recommended Actions:[/bold cyan]\n")
    
    if action == 'SEEK_DECRYPTOR':
        console.print("[bold green]✓ Family Identified - Seek Decryptor[/bold green]\n")
        console.print("1. [cyan]Visit NoMoreRansom.org:[/cyan]")
        console.print(f"   {family_info['nomoreransom']}\n")
        console.print("2. [cyan]Search for decryptor:[/cyan]")
        console.print(f"   Search for: \"{family_info['family']} decryptor\"\n")
        console.print("3. [cyan]Backup encrypted files:[/cyan]")
        console.print("   Make copies before attempting decryption\n")
        console.print("4. [cyan]Report to authorities:[/cyan]")
        console.print("   Consider reporting to law enforcement\n")
        
        if family_info.get('decryptor_available'):
            console.print("[bold green]⚡ Good news![/bold green] A decryptor is available for this family\n")
    
    elif action == 'FALSE_POSITIVE':
        console.print("[bold yellow]⚠ Possible False Positive[/bold yellow]\n")
        console.print("The file extension suggests ransomware, but entropy is low.")
        console.print("This could mean:")
        console.print("  • File was renamed but not actually encrypted")
        console.print("  • Encryption failed or was incomplete")
        console.print("  • File is a decoy or test file\n")
    
    elif action == 'UNKNOWN_FAMILY':
        console.print("[bold red]✗ Unknown Ransomware Family[/bold red]\n")
        console.print("The file appears encrypted but family is unknown.")
        console.print("\nRecommended steps:")
        console.print("  1. Upload ransom note to ID Ransomware (https://id-ransomware.malwarehunterteam.com/)")
        console.print("  2. Check NoMoreRansom.org for generic decryptors")
        console.print("  3. Consult cybersecurity professionals")
        console.print("  4. Report to local cyber crime unit\n")
    
    else:  # NOT_RANSOMWARE
        console.print("[bold green]✓ File Does Not Appear to be Ransomware[/bold green]\n")
        console.print("Analysis suggests this is not a ransomware-encrypted file.")
        console.print("The file may be:")
        console.print("  • A normal file")
        console.print("  • Corrupted data")
        console.print("  • Compressed archive")
        console.print("  • Other encryption (not ransomware)\n")
    
    # General resources
    console.print("[bold cyan]Useful Resources:[/bold cyan]\n")
    console.print("  • NoMoreRansom.org: https://www.nomoreransom.org/")
    console.print("  • ID Ransomware: https://id-ransomware.malwarehunterteam.com/")
    console.print("  • Emsisoft Decryptors: https://www.emsisoft.com/ransomware-decryption-tools/")
    console.print("  • Kaspersky Tools: https://www.kaspersky.com/downloads/thank-you/free-ransomware-decryptors")
    console.print("  • Avast Decryptors: https://www.avast.com/ransomware-decryption-tools\n")


def display_prevention_tips():
    """Display ransomware prevention tips"""
    console.print("[bold cyan]Prevention Tips (For Future):[/bold cyan]\n")
    console.print("  [green]✓[/green] Regular backups (3-2-1 rule)")
    console.print("  [green]✓[/green] Keep software updated")
    console.print("  [green]✓[/green] Use antivirus/anti-malware")
    console.print("  [green]✓[/green] Be cautious with email attachments")
    console.print("  [green]✓[/green] Enable email filtering")
    console.print("  [green]✓[/green] Restrict user permissions")
    console.print("  [green]✓[/green] Disable macros by default")
    console.print("  [green]✓[/green] Network segmentation")
    console.print("  [green]✓[/green] Employee security training\n")


def run():
    """Main entry point for ransomware helper"""
    display_banner()
    display_warning()
    
    # Get target file
    file_path = get_target_file()
    if not file_path:
        console.print("[yellow]Operation cancelled[/yellow]")
        return
    
    console.print(f"\n[green]✓[/green] Selected file: {file_path}\n")
    
    # Initialize identifier
    try:
        console.print("[cyan]Initializing ransomware identifier...[/cyan]")
        identifier = RansomwareIdentifier()
        console.print("[green]✓[/green] Identifier ready\n")
        
        # Analyze file
        with console.status("[bold cyan]Analyzing file...", spinner="dots"):
            results = identifier.analyze_file(file_path)
        
        console.print("[green]✓[/green] Analysis complete\n")
        console.print("═" * 70)
        console.print()
        
        # Display results
        display_file_info(results['file_info'])
        
        identified = display_family_identification(results['family_identification'])
        
        display_encryption_verification(results['encryption_verification'])
        
        # Recommendations
        display_recommendations(results)
        
        # Prevention
        display_prevention_tips()
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {str(e)}\n")
        return


if __name__ == "__main__":
    run()
