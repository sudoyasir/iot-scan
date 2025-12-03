"""Main CLI interface for IoT-Scan."""
import argparse
import sys
import logging
from typing import List, Dict

from src.scanner.arp_scan import ARPScanner
from src.scanner.port_scan import PortScanner
from src.scanner.fingerprint import DeviceFingerprint
from src.scanner.http_check import HTTPSecurityChecker
from src.scanner.mqtt_check import MQTTSecurityChecker
from src.scanner.ota_check import OTASecurityChecker
from src.utils.mac_vendor import MACVendorLookup
from src.utils.logger import get_logger
from src.utils.report import Report


class IoTScanner:
    """Main IoT scanning orchestrator."""
    
    def __init__(self, fast_mode: bool = False, verbose: bool = False):
        """Initialize IoT scanner.
        
        Args:
            fast_mode: Enable fast scan mode
            verbose: Enable verbose logging
        """
        self.fast_mode = fast_mode
        self.verbose = verbose
        
        # Set up logging
        log_level = logging.DEBUG if verbose else logging.INFO
        self.logger = get_logger(level=log_level)
        
        # Initialize components
        self.arp_scanner = ARPScanner()
        self.port_scanner = PortScanner()
        self.fingerprinter = DeviceFingerprint()
        self.http_checker = HTTPSecurityChecker()
        self.mqtt_checker = MQTTSecurityChecker()
        self.ota_checker = OTASecurityChecker()
        self.mac_lookup = MACVendorLookup()
    
    def scan(self, subnet: str) -> List[Dict]:
        """Perform complete IoT security scan.
        
        Args:
            subnet: Target subnet (e.g., "192.168.1.0/24")
            
        Returns:
            List of scanned devices with vulnerabilities
        """
        scan_type = "fast" if self.fast_mode else "full"
        
        # Print banner and scan info
        Report.print_banner()
        Report.print_scan_info(subnet, scan_type)
        
        # Step 1: Discover devices
        Report.print_progress("Discovering devices via ARP scan...")
        devices = self.arp_scanner.scan(subnet)
        
        if not devices:
            Report.print_error("No devices found. Make sure you're on the correct network.")
            return []
        
        Report.print_success(f"Found {len(devices)} devices")
        
        # Step 2: Scan and analyze each device
        scanned_devices = []
        
        for idx, device in enumerate(devices, 1):
            ip = device['ip']
            mac = device['mac']
            
            Report.print_progress(f"[{idx}/{len(devices)}] Scanning {ip}...")
            
            # Get vendor information
            vendor, device_type, common_devices = self.mac_lookup.lookup(mac)
            device['vendor'] = vendor or "Unknown"
            
            # Port scanning
            self.logger.debug(f"Port scanning {ip}...")
            open_ports = self.port_scanner.scan(ip, fast_mode=self.fast_mode)
            device['open_ports'] = [p['port'] for p in open_ports]
            device['port_details'] = open_ports
            
            # Skip devices with no open ports
            if not open_ports:
                self.logger.debug(f"No open ports on {ip}, skipping...")
                continue
            
            # Device fingerprinting
            self.logger.debug(f"Fingerprinting {ip}...")
            fingerprint = self.fingerprinter.identify_device(ip, mac, vendor, open_ports)
            device['device_type'] = fingerprint.get('device_type', 'Unknown')
            device['confidence'] = fingerprint.get('confidence', 'low')
            device['characteristics'] = fingerprint.get('characteristics', [])
            
            # Security checks
            vulnerabilities = []
            
            # HTTP security check
            if any(p['port'] in [80, 443, 8080, 8081, 8000] for p in open_ports):
                self.logger.debug(f"Checking HTTP security on {ip}...")
                http_vulns = self.http_checker.check_device(ip, open_ports)
                vulnerabilities.extend(http_vulns)
            
            # MQTT security check
            if any(p['port'] in [1883, 8883] for p in open_ports):
                self.logger.debug(f"Checking MQTT security on {ip}...")
                mqtt_vulns = self.mqtt_checker.check_device(ip, open_ports)
                vulnerabilities.extend(mqtt_vulns)
            
            # OTA and RTSP check
            if any(p['port'] in [80, 443, 8080, 554] for p in open_ports):
                self.logger.debug(f"Checking OTA/RTSP security on {ip}...")
                ota_vulns = self.ota_checker.check_device(ip, open_ports)
                vulnerabilities.extend(ota_vulns)
            
            device['vulnerabilities'] = vulnerabilities
            scanned_devices.append(device)
        
        # Display results
        Report.print_device_summary(scanned_devices)
        
        # Display vulnerability report
        if scanned_devices:
            Report.print_vulnerability_report(scanned_devices)
        
        return scanned_devices


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="IoT-Scan: Discover and scan IoT devices for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan local subnet
  iot-scan --subnet 192.168.1.0/24
  
  # Fast scan (fewer ports)
  iot-scan --subnet 192.168.1.0/24 --fast
  
  # Full scan with verbose output
  iot-scan --subnet 192.168.1.0/24 --full --verbose
  
  # Export results to JSON
  iot-scan --subnet 192.168.1.0/24 --json results.json
  
  # Auto-detect subnet
  iot-scan --auto

Note: ARP scanning requires root/administrator privileges.
Run with: sudo iot-scan [options]
        """
    )
    
    parser.add_argument(
        '--subnet',
        type=str,
        help='Target subnet in CIDR notation (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--auto',
        action='store_true',
        help='Auto-detect local subnet'
    )
    
    parser.add_argument(
        '--fast',
        action='store_true',
        help='Fast scan mode (scan fewer ports)'
    )
    
    parser.add_argument(
        '--full',
        action='store_true',
        help='Full scan mode (scan all IoT-related ports)'
    )
    
    parser.add_argument(
        '--json',
        type=str,
        metavar='FILE',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output (debug logging)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='IoT-Scan v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.subnet and not args.auto:
        parser.print_help()
        sys.exit(1)
    
    # Auto-detect subnet
    if args.auto:
        local_ip = ARPScanner.get_local_ip()
        subnet = ARPScanner.guess_subnet(local_ip)
        print(f"Auto-detected subnet: {subnet}")
    else:
        subnet = args.subnet
    
    # Determine scan mode
    fast_mode = args.fast
    if args.full:
        fast_mode = False
    
    # Initialize scanner
    scanner = IoTScanner(fast_mode=fast_mode, verbose=args.verbose)
    
    # Run scan
    try:
        results = scanner.scan(subnet)
        
        # Export to JSON if requested
        if args.json and results:
            Report.export_json(results, args.json)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        Report.print_error(f"Scan failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
