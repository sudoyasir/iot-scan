"""IoT device fingerprinting and identification."""
import logging
from typing import List, Dict, Optional
import requests
import hashlib

logger = logging.getLogger("iot-scan")


class DeviceFingerprint:
    """Device fingerprinting and identification."""
    
    # IoT device signatures based on HTTP headers
    IOT_SIGNATURES = {
        "ESP8266": ["ESP8266", "espressif"],
        "ESP32": ["ESP32", "espressif"],
        "Arduino": ["Arduino"],
        "Raspberry Pi": ["Raspbian", "RaspberryPi"],
        "Shelly": ["Shelly"],
        "Sonoff": ["Sonoff", "eWeLink"],
        "Tasmota": ["Tasmota"],
        "Home Assistant": ["Home Assistant"],
        "Node-RED": ["Node-RED"],
        "IP Camera": ["IP Camera", "IPCamera", "IPCAM", "Hikvision", "Dahua"],
        "NVR/DVR": ["NVR", "DVR", "Hikvision", "Dahua"],
        "Smart Plug": ["Smart Plug", "TP-LINK"],
        "Xiaomi": ["Xiaomi", "MiIO"],
        "Tuya": ["Tuya"],
    }
    
    def __init__(self, timeout: int = 3):
        """Initialize device fingerprint.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
    
    def identify_device(
        self,
        ip: str,
        mac: str,
        vendor: Optional[str],
        open_ports: List[Dict]
    ) -> Dict[str, str]:
        """Identify device type and characteristics.
        
        Args:
            ip: Device IP address
            mac: Device MAC address
            vendor: Vendor name from MAC lookup
            open_ports: List of open ports
            
        Returns:
            Dictionary with device identification info
        """
        device_info = {
            'device_type': 'Unknown',
            'confidence': 'low',
            'characteristics': []
        }
        
        # Check vendor-based identification
        if vendor:
            device_info['characteristics'].append(f"Vendor: {vendor}")
            
            # High confidence IoT identification based on vendor
            vendor_lower = vendor.lower()
            if any(x in vendor_lower for x in ['espressif', 'sonoff', 'shelly', 'tuya']):
                device_info['device_type'] = 'IoT Device'
                device_info['confidence'] = 'high'
            elif 'hikvision' in vendor_lower or 'dahua' in vendor_lower or 'axis' in vendor_lower:
                device_info['device_type'] = 'IP Camera / NVR'
                device_info['confidence'] = 'high'
            elif 'xiaomi' in vendor_lower:
                device_info['device_type'] = 'Smart Home Device'
                device_info['confidence'] = 'high'
            elif 'tp-link' in vendor_lower or 'tplink' in vendor_lower:
                device_info['device_type'] = 'Smart Home / Network Device'
                device_info['confidence'] = 'medium'
            elif 'raspberry' in vendor_lower:
                device_info['device_type'] = 'Single Board Computer'
                device_info['confidence'] = 'high'
        
        # Port-based fingerprinting
        port_numbers = [p['port'] for p in open_ports]
        
        if 554 in port_numbers:  # RTSP
            device_info['characteristics'].append("RTSP streaming (likely camera)")
            if device_info['device_type'] == 'Unknown':
                device_info['device_type'] = 'IP Camera'
                device_info['confidence'] = 'medium'
        
        if 1883 in port_numbers or 8883 in port_numbers:  # MQTT
            device_info['characteristics'].append("MQTT broker/client")
            if device_info['device_type'] == 'Unknown':
                device_info['device_type'] = 'IoT Device'
                device_info['confidence'] = 'medium'
        
        if 23 in port_numbers:  # Telnet
            device_info['characteristics'].append("Telnet (insecure)")
        
        if 8266 in port_numbers:  # ESP8266 common port
            device_info['characteristics'].append("ESP8266 device detected")
            device_info['device_type'] = 'ESP8266 IoT Device'
            device_info['confidence'] = 'high'
        
        # HTTP-based fingerprinting
        if 80 in port_numbers or 8080 in port_numbers:
            http_fingerprint = self._fingerprint_http(ip, port_numbers)
            if http_fingerprint:
                device_info.update(http_fingerprint)
        
        return device_info
    
    def _fingerprint_http(self, ip: str, ports: List[int]) -> Optional[Dict]:
        """Fingerprint device via HTTP.
        
        Args:
            ip: Device IP address
            ports: List of open ports
            
        Returns:
            Device fingerprint info or None
        """
        # Try common HTTP ports
        http_ports = [p for p in ports if p in [80, 443, 8080, 8081, 8000]]
        
        for port in http_ports:
            try:
                protocol = "https" if port == 443 else "http"
                url = f"{protocol}://{ip}:{port}"
                
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Extract headers
                server = response.headers.get('Server', '')
                content_type = response.headers.get('Content-Type', '')
                
                # Check for IoT signatures in headers
                headers_text = str(response.headers).lower()
                
                for device_type, signatures in self.IOT_SIGNATURES.items():
                    for signature in signatures:
                        if signature.lower() in headers_text or signature.lower() in response.text[:500].lower():
                            return {
                                'device_type': device_type,
                                'confidence': 'high',
                                'http_server': server,
                                'characteristics': [f"HTTP Server: {server}"]
                            }
                
                # Check for common IoT keywords in page content
                content_lower = response.text[:1000].lower()
                if any(x in content_lower for x in ['esp8266', 'esp32', 'firmware', 'iot', 'sensor']):
                    return {
                        'device_type': 'IoT Device',
                        'confidence': 'medium',
                        'http_server': server,
                        'characteristics': [f"HTTP Server: {server}", "IoT keywords detected"]
                    }
                
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                logger.debug(f"HTTP fingerprint error on {ip}:{port}: {str(e)}")
                continue
        
        return None
    
    @staticmethod
    def calculate_favicon_hash(url: str, timeout: int = 3) -> Optional[str]:
        """Calculate favicon hash for device identification.
        
        Args:
            url: URL to fetch favicon from
            timeout: Request timeout
            
        Returns:
            MD5 hash of favicon or None
        """
        try:
            response = requests.get(f"{url}/favicon.ico", timeout=timeout, verify=False)
            if response.status_code == 200:
                return hashlib.md5(response.content).hexdigest()
        except:
            pass
        return None
