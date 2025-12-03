#!/usr/bin/env python3
"""
Quick verification script for IoT-Scan installation.

This script verifies that all modules can be imported
and basic functionality works.
"""

import sys
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


def test_imports():
    """Test that all modules can be imported."""
    console.print("\n[cyan]Testing module imports...[/cyan]")
    
    modules = [
        ("src.scanner.arp_scan", "ARPScanner"),
        ("src.scanner.port_scan", "PortScanner"),
        ("src.scanner.fingerprint", "DeviceFingerprint"),
        ("src.scanner.http_check", "HTTPSecurityChecker"),
        ("src.scanner.mqtt_check", "MQTTSecurityChecker"),
        ("src.scanner.ota_check", "OTASecurityChecker"),
        ("src.utils.mac_vendor", "MACVendorLookup"),
        ("src.utils.logger", "get_logger"),
        ("src.utils.report", "Report"),
    ]
    
    results = []
    all_passed = True
    
    for module_name, class_name in modules:
        try:
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            results.append((module_name, "✓", "green"))
        except ImportError as e:
            results.append((module_name, f"✗ {str(e)}", "red"))
            all_passed = False
        except AttributeError as e:
            results.append((module_name, f"✗ {str(e)}", "red"))
            all_passed = False
    
    # Display results
    table = Table(title="Import Tests", box=box.ROUNDED)
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="white")
    
    for module, status, color in results:
        table.add_row(module, f"[{color}]{status}[/{color}]")
    
    console.print(table)
    return all_passed


def test_mac_vendor_lookup():
    """Test MAC vendor lookup."""
    console.print("\n[cyan]Testing MAC vendor lookup...[/cyan]")
    
    try:
        from src.utils.mac_vendor import MACVendorLookup
        
        lookup = MACVendorLookup()
        
        # Test Espressif MAC
        vendor, device_type, devices = lookup.lookup("30:AE:A4:12:34:56")
        
        if vendor == "Espressif Inc.":
            console.print("[green]✓[/green] MAC vendor lookup working")
            return True
        else:
            console.print("[red]✗[/red] MAC vendor lookup failed")
            return False
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {str(e)}")
        return False


def test_port_scanner():
    """Test port scanner."""
    console.print("\n[cyan]Testing port scanner...[/cyan]")
    
    try:
        from src.scanner.port_scan import PortScanner
        
        scanner = PortScanner()
        
        # Test service name mapping
        service = scanner._get_service_name(80)
        
        if service == "http":
            console.print("[green]✓[/green] Port scanner working")
            return True
        else:
            console.print("[red]✗[/red] Port scanner failed")
            return False
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {str(e)}")
        return False


def test_report_generation():
    """Test report generation."""
    console.print("\n[cyan]Testing report generation...[/cyan]")
    
    try:
        from src.utils.report import Report
        
        # Test banner printing
        Report.print_banner()
        
        console.print("[green]✓[/green] Report generation working")
        return True
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {str(e)}")
        return False


def check_dependencies():
    """Check required dependencies."""
    console.print("\n[cyan]Checking dependencies...[/cyan]")
    
    dependencies = [
        "scapy",
        "requests",
        "paho.mqtt.client",
        "rich",
    ]
    
    results = []
    all_installed = True
    
    for dep in dependencies:
        try:
            if dep == "paho.mqtt.client":
                __import__("paho.mqtt.client")
                dep_name = "paho-mqtt"
            else:
                __import__(dep)
                dep_name = dep
            results.append((dep_name, "✓", "green"))
        except ImportError:
            results.append((dep_name, "✗ Not installed", "red"))
            all_installed = False
    
    # Display results
    table = Table(title="Dependencies", box=box.ROUNDED)
    table.add_column("Package", style="cyan")
    table.add_column("Status", style="white")
    
    for dep, status, color in results:
        table.add_row(dep, f"[{color}]{status}[/{color}]")
    
    console.print(table)
    return all_installed


def main():
    """Run all verification tests."""
    console.print("\n[bold cyan]IoT-Scan Installation Verification[/bold cyan]")
    console.print("=" * 60)
    
    tests = [
        ("Dependencies", check_dependencies),
        ("Module Imports", test_imports),
        ("MAC Vendor Lookup", test_mac_vendor_lookup),
        ("Port Scanner", test_port_scanner),
        ("Report Generation", test_report_generation),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            console.print(f"\n[red]Error in {test_name}:[/red] {str(e)}")
            results[test_name] = False
    
    # Summary
    console.print("\n[bold]Summary[/bold]")
    console.print("=" * 60)
    
    summary_table = Table(box=box.SIMPLE)
    summary_table.add_column("Test", style="cyan")
    summary_table.add_column("Result", style="white")
    
    for test_name, passed in results.items():
        status = "[green]PASSED[/green]" if passed else "[red]FAILED[/red]"
        summary_table.add_row(test_name, status)
    
    console.print(summary_table)
    
    # Final verdict
    if all(results.values()):
        console.print("\n[bold green]✓ All tests passed! IoT-Scan is ready to use.[/bold green]")
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print("  1. Run: sudo python -m src.cli --auto")
        console.print("  2. Or: sudo python -m src.cli --subnet 192.168.1.0/24")
        console.print("  3. See QUICKSTART.md for more examples\n")
        return 0
    else:
        console.print("\n[bold red]✗ Some tests failed. Please check the errors above.[/bold red]")
        console.print("\n[cyan]Troubleshooting:[/cyan]")
        console.print("  1. Reinstall dependencies: pip install -r requirements.txt")
        console.print("  2. Check Python version: python --version (need 3.10+)")
        console.print("  3. See README.md for installation instructions\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
