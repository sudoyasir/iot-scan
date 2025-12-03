"""Report generation utility."""
import json
from datetime import datetime
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


console = Console()


class Report:
    """Report generator for scan results."""
    
    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    
    @staticmethod
    def print_banner() -> None:
        """Print IoT-Scan banner."""
        banner = """
╦╔═╗╔╦╗   ╔═╗╔═╗╔═╗╔╗╔
║║ ║ ║ ═══╚═╗║  ╠═╣║║║
╩╚═╝ ╩    ╚═╝╚═╝╩ ╩╝╚╝
IoT Device Security Scanner v1.0.0
        """
        console.print(Panel(banner, style="bold cyan", box=box.DOUBLE))
    
    @staticmethod
    def print_scan_info(subnet: str, scan_type: str) -> None:
        """Print scan information.
        
        Args:
            subnet: Target subnet
            scan_type: Type of scan (fast/full)
        """
        info_text = f"""
[bold]Target Subnet:[/bold] {subnet}
[bold]Scan Type:[/bold] {scan_type.upper()}
[bold]Start Time:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        console.print(Panel(info_text.strip(), title="Scan Configuration", border_style="blue"))
    
    @staticmethod
    def print_device_summary(devices: List[Dict[str, Any]]) -> None:
        """Print summary of discovered devices.
        
        Args:
            devices: List of device information
        """
        table = Table(title="Discovered Devices", box=box.ROUNDED)
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="green")
        table.add_column("Device Type", style="yellow")
        table.add_column("Open Ports", style="blue")
        
        for device in devices:
            ip = device.get('ip', 'N/A')
            mac = device.get('mac', 'N/A')
            vendor = device.get('vendor', 'Unknown')
            device_type = device.get('device_type', 'Unknown')
            ports = ', '.join(map(str, device.get('open_ports', [])))
            
            table.add_row(ip, mac, vendor, device_type, ports)
        
        console.print(table)
    
    @staticmethod
    def print_vulnerability_report(devices: List[Dict[str, Any]]) -> None:
        """Print vulnerability report for all devices.
        
        Args:
            devices: List of device information with vulnerabilities
        """
        console.print("\n")
        console.print(Panel("[bold]Vulnerability Report[/bold]", style="red", box=box.DOUBLE))
        
        total_vulns = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for device in devices:
            vulnerabilities = device.get('vulnerabilities', [])
            if not vulnerabilities:
                continue
            
            total_vulns += len(vulnerabilities)
            
            # Device header
            console.print(f"\n[bold cyan]Device: {device.get('ip')}[/bold cyan] ({device.get('vendor', 'Unknown')})")
            console.print(f"MAC: {device.get('mac', 'N/A')}")
            
            # Vulnerabilities table
            vuln_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            vuln_table.add_column("Severity", width=10)
            vuln_table.add_column("Vulnerability", width=70)
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'INFO')
                description = vuln.get('description', '')
                
                # Count severities
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                elif severity == "LOW":
                    low_count += 1
                
                severity_text = Text(severity, style=Report.SEVERITY_COLORS.get(severity, "white"))
                vuln_table.add_row(severity_text, description)
            
            console.print(vuln_table)
        
        # Summary
        if total_vulns > 0:
            summary = f"""
[bold red]CRITICAL:[/bold red] {critical_count}  [bold red]HIGH:[/bold red] {high_count}  [bold yellow]MEDIUM:[/bold yellow] {medium_count}  [bold blue]LOW:[/bold blue] {low_count}
[bold]Total Vulnerabilities:[/bold] {total_vulns}
            """
            console.print(Panel(summary.strip(), title="Summary", border_style="red"))
        else:
            console.print(Panel("[bold green]No vulnerabilities detected![/bold green]", border_style="green"))
    
    @staticmethod
    def export_json(devices: List[Dict[str, Any]], output_file: str) -> None:
        """Export scan results to JSON file.
        
        Args:
            devices: List of device information
            output_file: Output JSON file path
        """
        report_data = {
            "scan_date": datetime.now().isoformat(),
            "total_devices": len(devices),
            "devices": devices
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            console.print(f"\n[green]✓[/green] Report exported to: {output_file}")
        except Exception as e:
            console.print(f"\n[red]✗[/red] Failed to export report: {str(e)}")
    
    @staticmethod
    def print_progress(message: str, style: str = "cyan") -> None:
        """Print progress message.
        
        Args:
            message: Progress message
            style: Text style
        """
        console.print(f"[{style}]→[/{style}] {message}")
    
    @staticmethod
    def print_error(message: str) -> None:
        """Print error message.
        
        Args:
            message: Error message
        """
        console.print(f"[red]✗[/red] {message}")
    
    @staticmethod
    def print_success(message: str) -> None:
        """Print success message.
        
        Args:
            message: Success message
        """
        console.print(f"[green]✓[/green] {message}")
