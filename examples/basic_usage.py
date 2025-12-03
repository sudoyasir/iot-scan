#!/usr/bin/env python3
"""
Example usage of IoT-Scan library.

This script demonstrates how to use IoT-Scan programmatically
instead of using the CLI interface.
"""

import sys
from src.scanner.arp_scan import ARPScanner
from src.scanner.port_scan import PortScanner
from src.scanner.fingerprint import DeviceFingerprint
from src.scanner.http_check import HTTPSecurityChecker
from src.utils.mac_vendor import MACVendorLookup
from src.utils.report import Report


def scan_single_device(ip: str):
    """Scan a single device for vulnerabilities.
    
    Args:
        ip: Target IP address
    """
    print(f"\n[*] Scanning device: {ip}\n")
    
    # Initialize components
    port_scanner = PortScanner()
    fingerprinter = DeviceFingerprint()
    http_checker = HTTPSecurityChecker()
    
    # Port scan
    print("[+] Scanning ports...")
    open_ports = port_scanner.scan(ip, fast_mode=True)
    
    if not open_ports:
        print("[!] No open ports found")
        return
    
    print(f"[+] Found {len(open_ports)} open ports:")
    for port_info in open_ports:
        print(f"    - Port {port_info['port']}: {port_info['service']}")
    
    # Fingerprint device
    print("\n[+] Fingerprinting device...")
    fingerprint = fingerprinter.identify_device(ip, "", None, open_ports)
    print(f"    Device Type: {fingerprint['device_type']}")
    print(f"    Confidence: {fingerprint['confidence']}")
    
    # Security checks
    print("\n[+] Checking for vulnerabilities...")
    vulnerabilities = http_checker.check_device(ip, open_ports)
    
    if vulnerabilities:
        print(f"[!] Found {len(vulnerabilities)} vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"    [{vuln['severity']}] {vuln['description']}")
    else:
        print("[+] No vulnerabilities found")


def scan_network(subnet: str):
    """Scan entire network.
    
    Args:
        subnet: Target subnet (e.g., "192.168.1.0/24")
    """
    print(f"\n[*] Scanning network: {subnet}\n")
    
    # Initialize components
    arp_scanner = ARPScanner()
    mac_lookup = MACVendorLookup()
    
    # Discover devices
    print("[+] Discovering devices...")
    devices = arp_scanner.scan(subnet)
    
    if not devices:
        print("[!] No devices found")
        return
    
    print(f"[+] Found {len(devices)} devices:\n")
    
    # Display devices
    for device in devices:
        vendor = mac_lookup.get_vendor_name(device['mac'])
        print(f"    {device['ip']:<15} {device['mac']:<18} {vendor}")
    
    # Ask user if they want to scan all devices
    response = input("\n[?] Scan all devices for vulnerabilities? (y/n): ")
    
    if response.lower() == 'y':
        for device in devices:
            scan_single_device(device['ip'])
            print("\n" + "="*60)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <ip_address>         - Scan single device")
        print(f"  {sys.argv[0]} <subnet>            - Scan network (requires sudo)")
        print("\nExamples:")
        print(f"  {sys.argv[0]} 192.168.1.100")
        print(f"  sudo {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Determine if target is IP or subnet
    if '/' in target:
        # Network scan (requires root)
        import os
        if os.geteuid() != 0:
            print("[!] Network scanning requires root privileges")
            print("    Please run with: sudo python examples/basic_usage.py <subnet>")
            sys.exit(1)
        scan_network(target)
    else:
        # Single device scan
        scan_single_device(target)


if __name__ == '__main__':
    main()
