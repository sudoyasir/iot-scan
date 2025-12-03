"""ARP scanner for network device discovery."""
import logging
from typing import List, Dict, Tuple
from scapy.all import ARP, Ether, srp, conf
import socket

# Disable scapy verbose output
conf.verb = 0

logger = logging.getLogger("iot-scan")


class ARPScanner:
    """ARP scanner for discovering devices on local network."""
    
    def __init__(self, timeout: int = 3):
        """Initialize ARP scanner.
        
        Args:
            timeout: Timeout for ARP requests in seconds
        """
        self.timeout = timeout
    
    def scan(self, subnet: str) -> List[Dict[str, str]]:
        """Scan subnet for active devices using ARP.
        
        Args:
            subnet: Target subnet (e.g., "192.168.1.0/24")
            
        Returns:
            List of dictionaries with 'ip' and 'mac' keys
        """
        logger.info(f"Starting ARP scan on {subnet}")
        
        try:
            # Create ARP request packet
            arp_request = ARP(pdst=subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]
            
            devices = []
            for sent, received in answered_list:
                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc.upper()
                }
                devices.append(device_info)
                logger.debug(f"Found device: {device_info['ip']} - {device_info['mac']}")
            
            logger.info(f"ARP scan complete. Found {len(devices)} devices")
            return devices
            
        except PermissionError:
            logger.error("Permission denied. ARP scanning requires root/administrator privileges.")
            logger.error("Please run with sudo: sudo python -m src.cli --subnet <subnet>")
            return []
        except Exception as e:
            logger.error(f"ARP scan failed: {str(e)}")
            return []
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address.
        
        Returns:
            Local IP address
        """
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def guess_subnet(ip: str) -> str:
        """Guess subnet from IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Subnet in CIDR notation
        """
        octets = ip.split('.')
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return "192.168.1.0/24"
