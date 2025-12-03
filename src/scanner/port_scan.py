"""Asynchronous port scanner."""
import asyncio
import socket
import logging
from typing import List, Dict, Set, Optional

logger = logging.getLogger("iot-scan")


class PortScanner:
    """Asynchronous port scanner."""
    
    # Common IoT ports
    COMMON_IOT_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        80,    # HTTP
        443,   # HTTPS
        554,   # RTSP (cameras)
        1883,  # MQTT
        5000,  # UPnP/Flask
        5683,  # CoAP
        8000,  # HTTP Alt
        8008,  # HTTP Alt
        8080,  # HTTP Proxy
        8081,  # HTTP Alt
        8083,  # HTTP Alt
        8266,  # ESP8266
        8443,  # HTTPS Alt
        8883,  # MQTT over TLS
        9000,  # HTTP Alt
    ]
    
    FAST_SCAN_PORTS = [
        23,    # Telnet
        80,    # HTTP
        443,   # HTTPS
        554,   # RTSP
        1883,  # MQTT
        8080,  # HTTP Proxy
        8266,  # ESP8266
    ]
    
    def __init__(self, timeout: float = 1.0):
        """Initialize port scanner.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    async def _scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan a single port.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Dictionary with port info if open, None otherwise
        """
        try:
            # Create connection
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            
            # Try to get banner
            banner = None
            try:
                writer.write(b'\n')
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            port_info = {
                'port': port,
                'state': 'open',
                'service': self._get_service_name(port),
                'banner': banner
            }
            
            logger.debug(f"Port {port} open on {ip}")
            return port_info
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            logger.debug(f"Error scanning port {port} on {ip}: {str(e)}")
            return None
    
    async def scan_ports(self, ip: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports on a host.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            
        Returns:
            List of open ports with their information
        """
        logger.debug(f"Scanning {len(ports)} ports on {ip}")
        
        # Create scanning tasks
        tasks = [self._scan_port(ip, port) for port in ports]
        
        # Run all tasks concurrently
        results = await asyncio.gather(*tasks)
        
        # Filter out None results (closed ports)
        open_ports = [result for result in results if result is not None]
        
        logger.debug(f"Found {len(open_ports)} open ports on {ip}")
        return open_ports
    
    def scan(self, ip: str, fast_mode: bool = False) -> List[Dict]:
        """Synchronous wrapper for port scanning.
        
        Args:
            ip: Target IP address
            fast_mode: If True, scan only common ports
            
        Returns:
            List of open ports with their information
        """
        ports = self.FAST_SCAN_PORTS if fast_mode else self.COMMON_IOT_PORTS
        return asyncio.run(self.scan_ports(ip, ports))
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get service name for port.
        
        Args:
            port: Port number
            
        Returns:
            Service name
        """
        service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            554: "rtsp",
            1883: "mqtt",
            5000: "upnp",
            5683: "coap",
            8000: "http-alt",
            8008: "http-alt",
            8080: "http-proxy",
            8081: "http-alt",
            8083: "http-alt",
            8266: "esp8266",
            8443: "https-alt",
            8883: "mqtts",
            9000: "http-alt",
        }
        return service_map.get(port, "unknown")
    
    @staticmethod
    def has_iot_ports(open_ports: List[Dict]) -> bool:
        """Check if device has IoT-specific ports open.
        
        Args:
            open_ports: List of open port information
            
        Returns:
            True if IoT-related ports are detected
        """
        iot_indicators = {23, 1883, 8266, 554, 8883}
        port_numbers = {p['port'] for p in open_ports}
        return bool(port_numbers & iot_indicators)
