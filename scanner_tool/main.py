#!/usr/bin/env python3
"""
Multithreaded Port Scanner - Main Entry Point
A terminal-based network port scanning application with multithreading capabilities.
"""

import os
import sys
import socket
import argparse
import logging
import platform
from datetime import datetime
from typing import List, Dict, Union, Tuple

# Import local modules
from scanner_engine import ScannerEngine
from threading_module import ThreadingModule
from data_export_layer import DataExportLayer

# Import third-party libraries for terminal display
import colorama
from colorama import Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text

# Initialize colorama for cross-platform color support
colorama.init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

# Constants
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
VERSION = "1.0.0"
BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════╗
║  {Fore.RED}▄▄▄▄▄▄▄▄▄▄▄  {Fore.GREEN}▄▄▄▄▄▄▄▄▄▄▄  {Fore.BLUE}▄▄       ▄▄  {Fore.YELLOW}▄▄▄▄▄▄▄▄▄▄▄   {Fore.BLUE}║
║  {Fore.RED}▐░░░░░░░░░░░▌{Fore.GREEN}▐░░░░░░░░░░░▌{Fore.BLUE}▐░░▌     {Fore.BLUE}▐░░▌{Fore.YELLOW}▐░░░░░░░░░░░▌  {Fore.BLUE}║
║  {Fore.RED}▐░█▀▀▀▀▀▀▀█░▌{Fore.GREEN}▐░█▀▀▀▀▀▀▀█░▌{Fore.BLUE}▐░▌░▌   {Fore.BLUE}▐░▐░▌{Fore.YELLOW}▐░█▀▀▀▀▀▀▀▀▀   {Fore.BLUE}║
║  {Fore.RED}▐░▌       ▐░▌{Fore.GREEN}▐░▌       ▐░▌{Fore.BLUE}▐░▌▐░▌ {Fore.BLUE}▐░▌▐░▌{Fore.YELLOW}▐░▌            {Fore.BLUE}║
║  {Fore.RED}▐░█▄▄▄▄▄▄▄█░▌{Fore.GREEN}▐░▌       ▐░▌{Fore.BLUE}▐░▌ ▐░▐░▌ {Fore.BLUE}▐░▌{Fore.YELLOW}▐░█▄▄▄▄▄▄▄▄▄   {Fore.BLUE}║
║  {Fore.RED}▐░░░░░░░░░░░▌{Fore.GREEN}▐░▌       ▐░▌{Fore.BLUE}▐░▌  ▐░▌  {Fore.BLUE}▐░▌{Fore.YELLOW}▐░░░░░░░░░░░▌  {Fore.BLUE}║
║  {Fore.RED}▐░█▀▀▀▀▀▀▀█░▌{Fore.GREEN}▐░▌       ▐░▌{Fore.BLUE}▐░▌   ▀   {Fore.BLUE}▐░▌{Fore.YELLOW}▐░█▀▀▀▀▀▀▀▀▀   {Fore.BLUE}║
║  {Fore.RED}▐░▌       ▐░▌{Fore.GREEN}▐░▌       ▐░▌{Fore.BLUE}▐░▌       {Fore.BLUE}▐░▌{Fore.YELLOW}▐░▌            {Fore.BLUE}║
║  {Fore.RED}▐░▌       ▐░▌{Fore.GREEN}▐░█▄▄▄▄▄▄▄█░▌{Fore.BLUE}▐░▌       {Fore.BLUE}▐░▌{Fore.YELLOW}▐░█▄▄▄▄▄▄▄▄▄   {Fore.BLUE}║
║  {Fore.RED}▐░▌       ▐░▌{Fore.GREEN}▐░░░░░░░░░░░▌{Fore.BLUE}▐░▌       {Fore.BLUE}▐░▌{Fore.YELLOW}▐░░░░░░░░░░░▌  {Fore.BLUE}║
║  {Fore.RED}▀         ▀  {Fore.GREEN}▀▀▀▀▀▀▀▀▀▀▀ {Fore.BLUE} ▀         {Fore.BLUE}▀  {Fore.YELLOW}▀▀▀▀▀▀▀▀▀▀▀   {Fore.BLUE}║
╚══════════════════════════════════════════════════════════╝

{Fore.GREEN}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠉⠉⠉⠉⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄{Fore.RED}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Fore.GREEN}⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

{Fore.WHITE}Multi-Threaded Port Scanner v{VERSION}
{Fore.BLUE}=====================================
{Fore.CYAN}Discover network services with precision.
"""

class PortScanner:
    """Main port scanner class that orchestrates the scanning process."""
    
    def __init__(self):
        """Initialize the port scanner with its components."""
        self.scanner_engine = ScannerEngine()
        self.threading_module = ThreadingModule()
        self.data_export = DataExportLayer()
        self.console = Console()
        
    def validate_host(self, host: str) -> bool:
        """
        Validate if the provided host is reachable.
        
        Args:
            host: The hostname or IP address to validate
            
        Returns:
            bool: True if host is valid, False otherwise
        """
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False
    
    def parse_port_range(self, port_range: str) -> List[int]:
        """
        Parse port range string into a list of port numbers.
        
        Args:
            port_range: String representing port range (e.g., "80,443,8000-8100")
            
        Returns:
            List[int]: List of port numbers to scan
        """
        ports = []
        if not port_range:
            return DEFAULT_PORTS
            
        sections = port_range.split(',')
        for section in sections:
            if '-' in section:
                start, end = map(int, section.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(section))
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def display_scan_summary(self, host: str, open_ports: Dict[int, Dict], start_time: datetime):
        """
        Display a summary of the scan results.
        
        Args:
            host: The hostname or IP address scanned
            open_ports: Dictionary of open ports and their data including service and banner info
            start_time: Time when scan started
        """
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        table = Table(title=f"Scan Results for {host}")
        table.add_column("Port", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        table.add_column("Server", style="blue")
        
        for port, port_data in open_ports.items():
            service = port_data.get("service", "")
            version = port_data.get("version", "")
            server = port_data.get("server", "")
            
            table.add_row(
                str(port),
                "Open", 
                service,
                version,
                server
            )
            
        self.console.print(Panel(table))
        
        # If there's SSL certificate information, display it in a separate table
        ssl_tables_shown = False
        for port, port_data in open_ports.items():
            ssl_cert = port_data.get("ssl_cert", {})
            if ssl_cert and any(ssl_cert.values()):
                if not ssl_tables_shown:
                    self.console.print("\n[bold cyan]SSL Certificate Information:[/]")
                    ssl_tables_shown = True
                
                ssl_table = Table(title=f"SSL Certificate on Port {port}")
                ssl_table.add_column("Property", style="cyan")
                ssl_table.add_column("Value", style="yellow")
                
                for key, value in ssl_cert.items():
                    if value:  # Only show non-empty values
                        # Format the key for display
                        display_key = key.replace("_", " ").title()
                        ssl_table.add_row(display_key, value)
                
                self.console.print(ssl_table)
        
        # Display banner information if available
        banners_shown = False
        for port, port_data in open_ports.items():
            banner = port_data.get("banner", "")
            if banner:
                if not banners_shown:
                    self.console.print("\n[bold cyan]Service Banners:[/]")
                    banners_shown = True
                
                self.console.print(f"[bold green]Port {port} Banner:[/]")
                self.console.print(Panel(banner, title=f"Port {port}", width=100))
        
        summary = Text()
        summary.append("\nScan Summary:\n", style="bold cyan")
        summary.append(f"Target: ", style="bold")
        summary.append(f"{host}\n", style="yellow")
        summary.append(f"Time Started: ", style="bold")
        summary.append(f"{start_time.strftime('%Y-%m-%d %H:%M:%S')}\n", style="green")
        summary.append(f"Duration: ", style="bold")
        summary.append(f"{scan_duration:.2f} seconds\n", style="green")
        summary.append(f"Open Ports: ", style="bold")
        summary.append(f"{len(open_ports)}\n", style="red")
        
        self.console.print(Panel(summary, title="Scan Details"))
        
    def run_scan(self, host: str, ports: List[int], threads: int):
        """
        Run the port scan on the specified host and ports.
        
        Args:
            host: The hostname or IP address to scan
            ports: List of ports to scan
            threads: Number of threads to use for scanning
        """
        if not self.validate_host(host):
            print(f"{Fore.RED}[ERROR] Invalid host: {host}")
            return
        
        try:
            ip_address = socket.gethostbyname(host)
            print(f"{Fore.CYAN}[INFO] Scanning target: {host} ({ip_address})")
            
            start_time = datetime.now()
            print(f"{Fore.CYAN}[INFO] Scan started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.CYAN}[INFO] Scanning {len(ports)} ports with {threads} threads")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Scanning ports...", total=len(ports))
                
                # Create a callback to update progress
                def update_progress(port_number, status):
                    progress.update(task, advance=1)
                
                # Run the scan with the progress callback
                scan_results = self.scanner_engine.scan_ports(
                    host, 
                    ports, 
                    self.threading_module, 
                    threads,
                    progress_callback=update_progress
                )
            
            # Display results
            if scan_results:
                self.display_scan_summary(host, scan_results, start_time)
            else:
                print(f"{Fore.YELLOW}[WARNING] No open ports found on {host}")
                
            # Offer to export results
            self.offer_export_options(host, scan_results)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[INFO] Scan interrupted by user")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] An error occurred: {e}")
    
    def offer_export_options(self, host: str, scan_results: Dict[int, Dict]):
        """
        Offer options to export scan results.
        
        Args:
            host: The hostname or IP address scanned
            scan_results: Dictionary of open ports and their detailed information
        """
        if not scan_results:
            return
            
        print(f"\n{Fore.CYAN}[INFO] Export options:")
        print(f"{Fore.CYAN}[1] Export to CSV")
        print(f"{Fore.CYAN}[2] Export to Excel")
        print(f"{Fore.CYAN}[3] Export to PDF")
        print(f"{Fore.CYAN}[0] Skip export")
        
        try:
            choice = input(f"{Fore.GREEN}Enter your choice (0-3): ")
            
            if choice == "1":
                filename = f"{host}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                self.data_export.export_to_csv(scan_results, host, filename)
                print(f"{Fore.GREEN}[SUCCESS] Results exported to {filename}")
            elif choice == "2":
                filename = f"{host}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                self.data_export.export_to_excel(scan_results, host, filename)
                print(f"{Fore.GREEN}[SUCCESS] Results exported to {filename}")
            elif choice == "3":
                filename = f"{host}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                self.data_export.export_to_pdf(scan_results, host, filename)
                print(f"{Fore.GREEN}[SUCCESS] Results exported to {filename}")
            else:
                print(f"{Fore.CYAN}[INFO] Export skipped")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Export failed: {e}")

def validate_args(args):
    """
    Validate the command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        bool: True if arguments are valid, False otherwise
    """
    if not args.target:
        print(f"{Fore.RED}[ERROR] No target specified")
        return False
        
    if args.ports:
        try:
            for part in args.ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if start < 1 or end > 65535 or start > end:
                        print(f"{Fore.RED}[ERROR] Invalid port range: {part}")
                        return False
                else:
                    port = int(part)
                    if port < 1 or port > 65535:
                        print(f"{Fore.RED}[ERROR] Invalid port: {port}")
                        return False
        except ValueError:
            print(f"{Fore.RED}[ERROR] Invalid port specification: {args.ports}")
            return False
            
    if args.threads < 1:
        print(f"{Fore.RED}[ERROR] Thread count must be at least 1")
        return False
        
    return True

def setup_args():
    """
    Setup and parse command line arguments.
    
    Returns:
        Namespace: The parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Multithreaded Port Scanner - A terminal-based network scanning tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-t", "--target", help="Target host to scan (IP address or hostname)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443,8000-8100). Default: common ports")
    parser.add_argument("-n", "--threads", type=int, default=10, help="Number of threads to use for scanning. Default: 10")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version=f"Multithreaded Port Scanner v{VERSION}")
    
    args = parser.parse_args()
    
    # Check for Windows environment
    if platform.system() != "Windows":
        print(f"{Fore.YELLOW}[WARNING] This tool is optimized for Windows OS. Some features may not work as expected.")
    
    # If no args provided, show interactive prompt
    if len(sys.argv) == 1:
        print(BANNER)
        args.target = input(f"{Fore.CYAN}Enter target host (IP or hostname): ")
        port_input = input(f"{Fore.CYAN}Enter ports to scan (e.g., 80,443,8000-8100) or press enter for default: ")
        args.ports = port_input if port_input else None
        thread_input = input(f"{Fore.CYAN}Enter number of threads (default: 10): ")
        args.threads = int(thread_input) if thread_input else 10
    
    return args

def main():
    """Main entry point of the application."""
    args = setup_args()
    
    if not validate_args(args):
        return
    
    if not args.verbose:
        logging.basicConfig(level=logging.WARNING)
    
    scanner = PortScanner()
    ports = scanner.parse_port_range(args.ports)
    
    print(BANNER)
    scanner.run_scan(args.target, ports, args.threads)

if __name__ == "__main__":
    main()
